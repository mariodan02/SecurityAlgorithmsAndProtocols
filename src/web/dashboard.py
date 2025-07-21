# =============================================================================
# DASHBOARD CREDENZIALI ACCADEMICHE - Applicazione Principale
# File: web/dashboard.py
# Sistema Decentralizzato di Credenziali Accademiche
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

# Dipendenze FastAPI e web
from fastapi import FastAPI, Query, Request, HTTPException, Depends, Form, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from httpx import request
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_302_FOUND, HTTP_403_FORBIDDEN

from credentials.models import CredentialFactory, CredentialStatus
from wallet.presentation import PresentationFormat, PresentationManager
from wallet.student_wallet import AcademicStudentWallet, WalletConfiguration, WalletStatus
from pki.ocsp_client import OCSPClient, OCSPStatus
from pki.certificate_manager import CertificateManager

# Importazioni condizionali per prevenire errori se i moduli non sono disponibili
try:
    from credentials.models import AcademicCredential, PersonalInfo, StudyPeriod, StudyProgram, Course, ExamGrade, GradeSystem, EQFLevel, StudyType, University
    from credentials.issuer import AcademicCredentialIssuer, IssuerConfiguration
    from crypto.foundations import CryptoUtils
    MODULES_AVAILABLE = True
except ImportError as e:
    print(f"Moduli principali non disponibili: {e}")
    MODULES_AVAILABLE = False

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate

# =============================================================================
# MODELLI DEI DATI E CONFIGURAZIONE
# =============================================================================

@dataclass
class AppConfig:
    """Configurazione centralizzata dell'applicazione."""
    secret_key: str = "Unisa2025"
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = True
    templates_dir: str = "./src/web/templates"
    static_dir: str = "./src/web/static"
    session_timeout_minutes: int = 60
    max_file_size_mb: int = 10
    secure_server_url: str = "https://localhost:8443"
    secure_server_api_key: str = "verifier_token"

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)

class CredentialImportRequest(BaseModel):
    credential_json: str

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
# SERVIZI E UTILITÀ
# =============================================================================

class AuthenticationService:
    """Servizio per la gestione dell'autenticazione."""

    VALID_USERS = {
        "studente_mariorossi": {"role": "studente", "university": "Università di Salerno"},
        "issuer_rennes": {"role": "issuer", "university": "Université de Rennes"},
        "verifier_unisa": {"role": "verifier", "university": "Università di Salerno"},
        "admin_system": {"role": "admin", "university": "Sistema Centrale"}
    }

    @classmethod
    def authenticate_user(cls, username: str, password: str) -> Optional[Dict[str, str]]:
        """Autentica un utente con username e password."""
        if username in cls.VALID_USERS and password == "Unisa2025":
            return cls.VALID_USERS[username]
        return None

    @classmethod
    def get_user_permissions(cls, role: str) -> List[str]:
        """Restituisce i permessi dell'utente in base al ruolo."""
        permissions_map = {
            "studente": ["read", "share"],
            "issuer": ["read", "write", "issue"],
            "verifier": ["read", "verify"],
            "admin": ["read", "write", "verify", "admin"]
        }
        return permissions_map.get(role, ["read"])

class SessionManager:
    """Gestisce le sessioni utente."""

    def __init__(self, timeout_minutes: int = 60):
        self.sessions: Dict[str, UserSession] = {}
        self.timeout_minutes = timeout_minutes

    def create_session(self, user_info: Dict[str, str], username: str) -> str:
        """Crea una nuova sessione utente."""
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
        """Recupera una sessione esistente."""
        if session_id not in self.sessions:
            return None

        session = self.sessions[session_id]

        if self._is_session_expired(session):
            del self.sessions[session_id]
            return None

        session.last_activity = datetime.datetime.now(datetime.timezone.utc)
        return session

    def destroy_session(self, session_id: str) -> None:
        """Distrugge una sessione."""
        self.sessions.pop(session_id, None)

    def _is_session_expired(self, session: UserSession) -> bool:
        """Controlla se una sessione è scaduta."""
        expiry_time = session.last_activity + datetime.timedelta(minutes=self.timeout_minutes)
        return datetime.datetime.now(datetime.timezone.utc) > expiry_time

class PresentationVerifier:
    """Gestisce la verifica completa delle presentazioni selettive."""

    def __init__(self, dashboard_instance):
        self.dashboard = dashboard_instance
        self.logger = dashboard_instance.logger
        self.ocsp_client = OCSPClient()
        self.cert_manager = CertificateManager()

        try:
            from crypto.foundations import CryptoUtils
            self.crypto_utils = CryptoUtils()
        except ImportError:
            self.logger.warning("CryptoUtils non disponibile - le verifiche Merkle potrebbero fallire")
            self.crypto_utils = None

    def _get_issuer_name_from_disclosure(self, disclosure: dict) -> Optional[str]:
        """Estrae il nome dell'emittente dagli attributi divulgati."""
        try:
            disclosed_attrs = disclosure.get("disclosed_attributes", {})
            for attr_path, attr_value in disclosed_attrs.items():
                if "issuer" in attr_path and "name" in attr_path:
                    return attr_value
            return None
        except Exception as e:
            self.logger.error(f"Errore durante l'estrazione del nome emittente: {e}")
            return None

    async def verify_presentation_complete(self, presentation_data: dict, student_public_key_pem: str, purpose: str, check_ocsp: bool) -> dict:
        """Esegue una verifica completa di una presentazione selettiva, includendo il controllo OCSP."""
        self.logger.info(f"🔍 Avvio verifica completa (OCSP: {check_ocsp})")

        report = {
            "credential_id": presentation_data.get("presentation_id", "sconosciuto"),
            "validation_level": "completo", 
            "overall_result": "sconosciuto",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "is_valid": False, 
            "errors": [], 
            "warnings": [], 
            "info": [],
            "technical_details": {
                "student_signature_valid": False, 
                "signature_valid": False,
                "merkle_tree_valid": False, 
                "blockchain_status": "non_controllato",
                "temporal_valid": False, 
                "ocsp_status": "non_controllato"
            }
        }

        try:
            # 1. VERIFICA DELLA FIRMA DELLO STUDENTE
            self.logger.info("1. Verifica firma studente...")
            student_sig_valid = await self._verify_student_signature(presentation_data, student_public_key_pem)
            report["technical_details"]["student_signature_valid"] = student_sig_valid
            if student_sig_valid:
                self.logger.info("Firma studente valida")
            else:
                self.logger.warning("Firma studente non valida")
                report["errors"].append({"code": "STUDENT_SIGNATURE_INVALID", "message": "Firma dello studente non valida"})

            # 2. ESTRAZIONE DELLE CREDENZIALI
            self.logger.info("2. Estrazione credenziali...")
            credentials = self._extract_credentials_from_presentation(presentation_data)
            if not credentials:
                report["errors"].append({"code": "NO_CREDENTIALS_FOUND", "message": "Nessuna credenziale trovata"})
                report["overall_result"] = "invalid"
                return report

            # 3. VERIFICA DI OGNI CREDENZIALE
            all_credentials_valid = True
            for i, cred_disclosure in enumerate(credentials):
                self.logger.info(f"3. Verifica credenziale {i+1}/{len(credentials)}...")

                # 3.1 VERIFICA DELLE PROVE DI MERKLE
                if "merkle_proofs" in cred_disclosure:
                    if self.logger.level <= logging.INFO:
                        await self._debug_merkle_structure(cred_disclosure)

                    merkle_valid, merkle_error = await self._verify_merkle_proofs(cred_disclosure, report)
                    if not merkle_valid:
                        if "proof non valida" in merkle_error.lower() or "numero attributi" in merkle_error.lower():
                            report["errors"].append({
                                "code": "MERKLE_PROOF_INVALID",
                                "message": f"Prova di Merkle crittograficamente non valida per la credenziale {i+1}: {merkle_error}"
                            })
                            all_credentials_valid = False
                        else:
                            report["warnings"].append({
                                "code": "MERKLE_PROOF_PARTIAL",
                                "message": f"Prova di Merkle parzialmente valida per la credenziale {i+1}: {merkle_error}"
                            })
                    else:
                        report["info"].append({
                            "code": "MERKLE_PROOF_VALID",
                            "message": f"Prova di Merkle crittograficamente verificata per la credenziale {i+1}"
                        })
                        if not merkle_error:
                            report["technical_details"]["merkle_tree_valid"] = True
                else:
                    report["warnings"].append({
                        "code": "NO_MERKLE_PROOFS",
                        "message": f"Nessuna prova di Merkle fornita per la credenziale {i+1}"
                    })

                # 3.2 VERIFICA FIRMA E OCSP
                issuer_name = self._get_issuer_name_from_disclosure(cred_disclosure)
                if issuer_name:
                    university_cert = await self._find_university_certificate(issuer_name)
                    if university_cert:
                        report["technical_details"]["signature_valid"] = True
                        report["info"].append({"code": "UNIVERSITY_CERT_FOUND", "message": f"Certificato per {issuer_name} trovato."})

                        # 3.3 CONTROLLO OCSP
                        if check_ocsp:
                            ocsp_status, ocsp_message = await self._verify_ocsp_status(university_cert)
                            report["technical_details"]["ocsp_status"] = ocsp_status
                            if ocsp_status == "revoked":
                                report["errors"].append({"code": "CERTIFICATE_REVOKED", "message": ocsp_message})
                                all_credentials_valid = False
                            elif ocsp_status != "good":
                                report["warnings"].append({"code": "OCSP_WARNING", "message": ocsp_message})
                    else:
                        report["warnings"].append({"code": "UNIVERSITY_CERT_MISSING", "message": f"Certificato per {issuer_name} non trovato."})

                # 3.4 VERIFICA STATO SULLA BLOCKCHAIN
                credential_id = cred_disclosure.get("credential_id")
                if credential_id:
                    blockchain_status = await self._verify_single_credential_id(credential_id)
                    report["technical_details"]["blockchain_status"] = blockchain_status

                    if blockchain_status == "revocato":
                        report["errors"].append({
                            "code": "CREDENTIAL_REVOKED",
                            "message": f"La credenziale {credential_id} risulta revocata"
                        })
                        all_credentials_valid = False
                    elif blockchain_status == "valido":
                        report["info"].append({
                            "code": "BLOCKCHAIN_VALID",
                            "message": f"Credenziale {credential_id} verificata su blockchain"
                        })
                    elif blockchain_status in ["timeout", "server irraggiungibile", "errore API", "errore client"]:
                        report["warnings"].append({
                            "code": "BLOCKCHAIN_UNREACHABLE",
                            "message": f"Impossibile verificare la blockchain per la credenziale {credential_id}: {blockchain_status}"
                        })
                    else:
                        report["warnings"].append({
                            "code": "BLOCKCHAIN_UNKNOWN",
                            "message": f"Stato blockchain sconosciuto per la credenziale {credential_id}: {blockchain_status}"
                        })

            # 4. VERIFICA TEMPORALE
            self.logger.info("4. Verifica temporale...")
            temporal_valid = self._verify_temporal_consistency(presentation_data)
            report["technical_details"]["temporal_valid"] = temporal_valid
            if not temporal_valid:
                report["warnings"].append({"code": "TEMPORAL_INCONSISTENCY", "message": "Rilevate inconsistenze temporali"})

            # 5. RISULTATO FINALE
            if any(e["code"] == "CERTIFICATE_REVOKED" for e in report["errors"]):
                report["overall_result"] = "revocato"
            elif len(report["errors"]) > 0:
                report["overall_result"] = "non valido"
            elif len(report["warnings"]) > 0:
                report["overall_result"] = "avviso"
                report["is_valid"] = True  # Valida ma con avvertenze
            else:
                report["overall_result"] = "valido"
                report["is_valid"] = True

            return report

        except Exception as e:
            self.logger.error(f"Errore durante la verifica: {e}")
            report["errors"].append({"code": "VERIFICATION_ERROR", "message": f"Errore interno: {str(e)}"})
            report["overall_result"] = "non valido"
            return report

    async def _verify_ocsp_status(self, issuer_cert: x509.Certificate) -> Tuple[str, str]:
        """Verifica lo stato di revoca del certificato dell'emittente tramite OCSP."""
        self.logger.info("Verifica stato di revoca OCSP...")
        try:
            # Carica il certificato della Root CA per la verifica
            ca_cert_path = "./certificates/ca/ca_certificate.pem"
            if not Path(ca_cert_path).exists():
                return "error", "Certificato della Root CA non trovato."

            ca_cert = self.cert_manager.load_certificate_from_file(ca_cert_path)

            response = self.ocsp_client.check_certificate_status(issuer_cert, ca_cert)

            if response.status == OCSPStatus.GOOD:
                self.logger.info("Stato OCSP: GOOD")
                return "good", "Il certificato dell'emittente è valido."
            elif response.status == OCSPStatus.REVOKED:
                self.logger.warning("Stato OCSP: REVOKED")
                return "revoked", "Il certificato dell'emittente è stato REVOCATO."
            else:
                self.logger.warning(f"Stato OCSP: {response.status.value}")
                return response.status.value, response.error_message or "Stato OCSP sconosciuto."

        except Exception as e:
            self.logger.error(f"Errore durante la verifica OCSP: {e}")
            return "error", str(e)

    async def _verify_student_signature(self, presentation_data: dict, student_public_key_pem: str) -> bool:
        """Verifica la firma digitale dello studente."""
        try:
            if "signature" not in presentation_data:
                self.logger.warning("Nessuna firma trovata nella presentazione")
                return False

            signature_info = presentation_data["signature"]

            try:
                # Pulisce la chiave PEM se necessario
                clean_key = student_public_key_pem.strip()
                if not clean_key.startswith("-----BEGIN"):
                    # Se la chiave non ha l'header, prova ad aggiungerlo
                    clean_key = f"-----BEGIN PUBLIC KEY-----\n{clean_key}\n-----END PUBLIC KEY-----"

                public_key = serialization.load_pem_public_key(clean_key.encode())
            except Exception as e:
                self.logger.error(f"Errore nel caricamento della chiave pubblica dello studente: {e}")
                return False

            # Ricostruisce i dati esatti che sono stati firmati
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
                self.logger.info("Firma studente valida")
            else:
                self.logger.warning("Firma studente non valida")
            return is_valid

        except Exception as e:
            self.logger.error(f"Errore nella verifica della firma dello studente: {e}")
            return False

    def _extract_credentials_from_presentation(self, presentation_data: dict) -> list:
        return presentation_data.get("selective_disclosures", [])

    async def _find_university_certificate(self, university_name: str) -> Optional[x509.Certificate]:
        """Trova il certificato di un'università."""
        try:
            self.logger.info(f"   🔍 Ricerca certificato per: {university_name}")

            # Prova prima tramite API, poi come fallback locale
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
                                self.logger.info(f"Certificato trovato: {cert_path}")
                                return cert
                except Exception:
                    continue

            self.logger.warning(f"Certificato non trovato per {university_name}")
            return None

        except Exception as e:
            self.logger.error(f"Errore nella ricerca del certificato: {e}")
            return None


    async def _verify_merkle_proofs(self, disclosure: dict, report: dict) -> Tuple[bool, str]:
        """
        Verifica crittografica delle prove di Merkle in modo sicuro, confrontando i dati
        presentati con quelli originali all'interno delle prove.
        """
        try:
            self.logger.info("🔐 Avvio verifica crittografica sicura delle prove di Merkle...")
            
            # 1. Estraiamo i dati necessari dalla presentazione
            original_merkle_root = disclosure.get("original_merkle_root")
            if not original_merkle_root:
                self.logger.error("❌ Merkle root originale assente dalla presentazione.")
                return False, "Merkle root originale mancante nella presentazione."

            disclosed_attributes = disclosure.get("disclosed_attributes", {})
            merkle_proofs = disclosure.get("merkle_proofs", [])

            # Il numero di attributi presentati deve corrispondere esattamente al numero di prove.
            if len(disclosed_attributes) != len(merkle_proofs):
                error_msg = f"Incoerenza critica: il numero di attributi presentati ({len(disclosed_attributes)}) non corrisponde al numero di prove crittografiche ({len(merkle_proofs)})."
                self.logger.error(error_msg)
                return False, error_msg

            if not merkle_proofs:
                return False, "La presentazione non contiene prove crittografiche da verificare."
        
            # Per ogni attributo presentato, troviamo la sua prova e verifichiamo che corrisponda.
            
            # Creiamo una mappa delle prove basata sul loro valore originale per un facile accesso.
            # Questo ci protegge da alterazioni dell'ordine.
            proofs_map = {
                json.dumps(p.get("attribute_value"), sort_keys=True): p
                for p in merkle_proofs
            }
            
            valid_proofs_count = 0
            
            # Iteriamo sui dati che vengono mostrati effettivamente durante presentazione selettiva
            for path, presented_value in disclosed_attributes.items():
                
                # Serializziamo il valore presentato per cercarlo nella mappa delle prove
                presented_value_key = json.dumps(presented_value, sort_keys=True)
                
                # Cerchiamo la prova crittografica corrispondente
                matching_proof = proofs_map.get(presented_value_key)
                
                # Se non esiste una prova per il dato presentato, la presentazione è stata alterata.
                if not matching_proof:
                    error_msg = f"Manomissione rilevata! L'attributo '{path}' con valore '{str(presented_value)[:50]}...' non ha una prova crittografica corrispondente."
                    self.logger.error(error_msg)
                    return False, error_msg
                
                # Ora eseguiamo la verifica crittografica usando il valore presentato
                is_valid = await self._verify_single_merkle_proof(
                    presented_value, 
                    matching_proof.get("proof_path", []),
                    original_merkle_root
                )

                if is_valid:
                    valid_proofs_count += 1
                    self.logger.info(f"✅ Prova VALIDA per l'attributo '{path}'.")
                else:
                    error_msg = f"Prova crittografica NON VALIDA per l'attributo '{path}'."
                    self.logger.error(error_msg)
                    # Se anche una sola prova fallisce, l'intera presentazione non è valida.
                    return False, error_msg
            
            # 4. RISULTATO FINALE
            if valid_proofs_count == len(disclosed_attributes):
                self.logger.info(f"SUCCESSO: Tutte le {valid_proofs_count} prove sono state verificate con successo.")
                report["technical_details"]["merkle_tree_valid"] = True
                return True, ""
            else:
                error_msg = f"FALLIMENTO: Solo {valid_proofs_count}/{len(disclosed_attributes)} prove sono risultate valide."
                self.logger.error(error_msg)
                report["technical_details"]["merkle_tree_valid"] = False
                return False, error_msg

        except Exception as e:
            self.logger.error(f"Errore critico durante la verifica Merkle: {e}", exc_info=True)
            return False, f"Errore interno del server durante la verifica: {e}"
    
    async def _verify_single_merkle_proof(self, attribute_value: Any, proof_path: List[Dict], merkle_root: str) -> bool:
        """
        Verifica crittograficamente una singola prova di Merkle REALE.
        """
        try:
            if not self.crypto_utils:
                self.logger.error("CryptoUtils non disponibile per la verifica Merkle")
                return False
            
            from credentials.models import DeterministicSerializer
            
            # Serializza il valore dell'attributo
            attribute_json = DeterministicSerializer.serialize_for_merkle(attribute_value)
            current_hash = self.crypto_utils.sha256_hash_string(attribute_json)
            
            self.logger.debug(f"🔍 Verifica prova Merkle:")
            self.logger.debug(f"   Valore: {str(attribute_value)[:50]}...")
            self.logger.debug(f"   Hash iniziale: {current_hash}")
            self.logger.debug(f"   Passi prova: {len(proof_path)}")
            
            # Ricostruisce il percorso verso la radice seguendo la prova
            for i, step in enumerate(proof_path):
                sibling_hash = step.get('hash')
                is_right_sibling = step.get('is_right', False)
                
                if not sibling_hash:
                    self.logger.warning(f"Hash mancante nel passo {i}")
                    return False
                
                # Combina l'hash corrente con il sibling secondo la direzione
                if is_right_sibling:
                    # Il sibling è a destra, quindi il nostro hash è a sinistra
                    combined = current_hash + sibling_hash
                else:
                    # Il sibling è a sinistra, quindi il nostro hash è a destra
                    combined = sibling_hash + current_hash
                
                # Calcola il nuovo hash per il passo successivo
                current_hash = self.crypto_utils.sha256_hash_string(combined)
                
                self.logger.debug(f"   Passo {i}: {sibling_hash[:16]}... ({'DX' if is_right_sibling else 'SX'}) -> {current_hash}")
            
            # Verifica che la radice calcolata corrisponda a quella attesa
            is_valid = current_hash == merkle_root
            
            if is_valid:
                self.logger.info(f"✅ Prova Merkle VALIDA - radice raggiunta: {current_hash}")
            else:
                self.logger.warning(f"❌ Prova Merkle NON VALIDA")
                self.logger.warning(f"   Radice calcolata: {current_hash}")
                self.logger.warning(f"   Radice attesa:    {merkle_root}")
                
                # Debug aggiuntivo per capire la discrepanza
                self.logger.debug(f"   Ultimo hash combinato: {combined if 'combined' in locals() else 'N/A'}")
            return is_valid
            
        except Exception as e:
            self.logger.error(f"Errore nella verifica della prova Merkle: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    async def _debug_merkle_structure(self, disclosure: dict):
        """
        Metodo di debug per analizzare la struttura delle prove di Merkle.
        """
        try:
            self.logger.info("DEBUG: Analisi struttura prova di Merkle")

            disclosed_attributes = disclosure.get("disclosed_attributes", {})
            merkle_proofs = disclosure.get("merkle_proofs", [])

            self.logger.info(f"Attributi divulgati: {len(disclosed_attributes)}")
            for i, (key, value) in enumerate(disclosed_attributes.items()):
                value_preview = str(value)[:50] + "..." if len(str(value)) > 50 else str(value)
                self.logger.info(f"      {i}: {key} = {value_preview}")

            self.logger.info(f"Prove di Merkle: {len(merkle_proofs)}")
            for i, proof in enumerate(merkle_proofs):
                self.logger.info(f"      Prova {i}:")
                self.logger.info(f"        Indice: {proof.get('attribute_index')}")
                self.logger.info(f"        Radice: {proof.get('merkle_root', 'N/A')[:16]}...")
                self.logger.info(f"        Passi: {len(proof.get('proof_path', []))}")

                for j, step in enumerate(proof.get('proof_path', [])):
                    side = "D" if step.get('is_right') else "S"
                    hash_preview = step.get('hash', 'N/A')[:16] + "..." if step.get('hash') else 'N/A'
                    self.logger.info(f"          Passo {j}: {hash_preview} ({side})")

        except Exception as e:
            self.logger.error(f"Errore nel debug di Merkle: {e}")

    async def _verify_blockchain_status(self, presentation_data: dict) -> str:
        """
        Estrae l'ID della credenziale originale dalla presentazione
        e ne verifica lo stato su blockchain.
        """
        try:
            original_credential_id = None
            if "selective_disclosures" in presentation_data and presentation_data["selective_disclosures"]:
                original_credential_id = presentation_data["selective_disclosures"][0].get("credential_id")

            if not original_credential_id:
                self.logger.error("ID della credenziale originale non trovato nella presentazione.")
                return "ID originale non trovato"

            self.logger.info(f"Trovato ID originale: {original_credential_id}. Verifica su blockchain...")
            return await self._verify_single_credential_id(original_credential_id)

        except Exception as e:
            self.logger.error(f"Errore nell'analisi della presentazione: {e}")
            return "errore analisi"

    async def _verify_single_credential_id(self, credential_id: str) -> str:
        """Verifica un singolo ID credenziale sulla blockchain."""
        try:
            url = f"{self.dashboard.config.secure_server_url}/api/v1/blockchain/credentials/verify"
            payload = {"credential_id": credential_id}

            async with httpx.AsyncClient(verify=False) as client:
                response = await client.post(
                    url,
                    headers={"Authorization": f"Bearer {self.dashboard.config.secure_server_api_key}"},
                    json=payload,
                    timeout=10.0,
                )

            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    status = result.get("blockchain_status", {}).get("status", "UNKNOWN").lower()
                    status_map = {
                        "valid": "valido",
                        "revoked": "revocato",
                        "not_found": "non registrato su blockchain",
                    }
                    return status_map.get(status, f"sconosciuto ({status})")
                else:
                    return "errore API"
            else:
                return "server irraggiungibile"
        except asyncio.TimeoutError:
            return "timeout"
        except Exception as e:
            self.logger.error(f"Errore client nella verifica dell'ID {credential_id}: {e}")
            return "errore client"


    def _verify_temporal_consistency(self, presentation_data: dict) -> bool:
        """Verifica la coerenza temporale della presentazione."""
        try:
            now = datetime.datetime.now(datetime.timezone.utc)

            expires_at_str = presentation_data.get("expires_at")
            if expires_at_str:
                # Gestione migliorata del fuso orario
                try:
                    if expires_at_str.endswith('Z'):
                        expires_at_str = expires_at_str[:-1] + '+00:00'
                    elif '+' not in expires_at_str and 'T' in expires_at_str:
                        expires_at_str += '+00:00'

                    expires_at = datetime.datetime.fromisoformat(expires_at_str)
                    if now > expires_at:
                        self.logger.warning("Presentazione scaduta")
                        return False
                except ValueError:
                    self.logger.warning(f"Formato data di scadenza non valido: {expires_at_str}")
                    return False

            return True
        except Exception as e:
            self.logger.error(f"Errore nella verifica temporale: {e}")
            return False

# =============================================================================
# MIDDLEWARE E DIPENDENZE
# =============================================================================

def get_current_user(request: Request, session_manager: SessionManager) -> Optional[UserSession]:
    """Dipendenza per ottenere l'utente corrente dalla sessione."""
    session_id = request.session.get("session_id")
    if session_id:
        return session_manager.get_session(session_id)
    return None

def require_auth(request: Request, session_manager: SessionManager) -> UserSession:
    """Dipendenza che richiede l'autenticazione."""
    user = get_current_user(request, session_manager)
    if not user:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Autenticazione richiesta"
        )
    return user

# =============================================================================
# CLASSE PRINCIPALE DELLA DASHBOARD
# =============================================================================

class AcademicCredentialsDashboard:
    """
    Dashboard principale per la gestione delle credenziali accademiche.
    """

    def __init__(self, config: Optional[AppConfig] = None):
        self.config = config or AppConfig()
        self.app = FastAPI(
            title="Dashboard Credenziali Accademiche",
            description="Sistema per la gestione decentralizzata delle credenziali accademiche.",
            version="2.0.0"
        )

        # Servizi
        self.session_manager = SessionManager(self.config.session_timeout_minutes)
        self.issuer = None  # Verrà inizializzato in seguito

        # Configurazione del logging
        self._setup_logging()

        # Inizializzazione dei componenti
        self._setup_directories()
        self._setup_templates()
        self._setup_middleware()
        self._setup_static_files()

        # Creazione delle dipendenze di autenticazione
        self.auth_deps = self._create_auth_dependencies()

        self._setup_routes()
        self._initialize_system_components()
        self._initialize_verification_service()

    def _setup_logging(self) -> None:
        """Configura il sistema di logging."""
        if not logging.root.handlers:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                force=True
            )
            
        for logger_name in ['credentials.issuer', 'credentials.validator']:
            logger = logging.getLogger(logger_name)
            logger.propagate = False

        self.logger = logging.getLogger(__name__)

    def run(self, host: Optional[str] = None, port: Optional[int] = None):
        """Avvia il server web."""
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
        Serializzatore JSON personalizzato per gestire datetime e altri oggetti non serializzabili.
        Versione migliorata per gestire tutti i tipi di oggetti delle credenziali accademiche.
        """
        # Gestione datetime
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, datetime.date):
            return obj.isoformat()
        
        # Gestione UUID
        elif isinstance(obj, uuid.UUID):
            return str(obj)
        
        # Gestione Enum (per CredentialStatus, StudyType, GradeSystem, etc.)
        elif hasattr(obj, 'value'):  # Enum objects
            return obj.value
        elif hasattr(obj, 'name'):   # Enum objects (alternative)
            return obj.name
        
        # Gestione oggetti Pydantic/custom con to_dict
        elif hasattr(obj, 'to_dict'):
            return obj.to_dict()
        elif hasattr(obj, 'model_dump'):  # Pydantic v2
            return obj.model_dump()
        elif hasattr(obj, 'dict'):       # Pydantic v1
            return obj.dict()
        
        # Gestione oggetti con __dict__
        elif hasattr(obj, '__dict__'):
            # Converte ricorsivamente usando questo serializzatore
            result = {}
            for key, value in obj.__dict__.items():
                try:
                    # Test se il valore è serializzabile
                    json.dumps(value, default=str)
                    result[key] = value
                except TypeError:
                    # Se non è serializzabile, usa il nostro serializzatore
                    result[key] = self._safe_json_serializer(value)
            return result
        
        # Gestione liste e dizionari
        elif isinstance(obj, list):
            return [self._safe_json_serializer(item) for item in obj]
        elif isinstance(obj, dict):
            return {key: self._safe_json_serializer(value) for key, value in obj.items()}
        
        # Gestione tipi numerici speciali
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        
        # Fallback finale: converte a stringa
        else:
            try:
                # Tenta di convertire direttamente a stringa
                return str(obj)
            except Exception:
                # Se tutto fallisce, restituisce una rappresentazione di debug
                return f"<{type(obj).__name__} object>"

    def _create_json_response(self, data: Dict[str, Any], status_code: int = 200) -> JSONResponse:
        """
        Crea una JSONResponse con serializzazione sicura.
        """
        try:
            json.dumps(data, default=str)
            return JSONResponse(data, status_code=status_code)
        except TypeError:
            safe_data = json.loads(json.dumps(data, default=self._safe_json_serializer))
            return JSONResponse(safe_data, status_code=status_code)

    def _setup_directories(self) -> None:
        """Crea le directory necessarie per l'applicazione."""
        self.templates_dir = Path(self.config.templates_dir)
        self.static_dir = Path(self.config.static_dir)
        self.wallets_dir = Path("./student_wallets")
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.static_dir.mkdir(parents=True, exist_ok=True)
        self.wallets_dir.mkdir(parents=True, exist_ok=True)

    def _setup_templates(self) -> None:
        """Configura il sistema di rendering dei template."""
        self.templates = Jinja2Templates(directory=str(self.templates_dir))

    def _setup_middleware(self) -> None:
        """Configura i middleware dell'applicazione."""
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
        """Configura la gestione dei file statici."""
        self.app.mount("/static", StaticFiles(directory=str(self.static_dir)), name="static")

    def _create_auth_dependencies(self):
        """Crea le dipendenze di autenticazione con controlli granulari."""

        def get_current_user_dep(request: Request) -> Optional[UserSession]:
            return get_current_user(request, self.session_manager)

        def require_auth_dep(request: Request) -> UserSession:
            user = get_current_user(request, self.session_manager)
            if not user:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Autenticazione richiesta")
            return user

        def require_issuer_dep(request: Request) -> UserSession:
            user = get_current_user(request, self.session_manager)
            if not user:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Autenticazione richiesta")
            if user.role != "issuer":
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Accesso riservato alle università emittenti")
            return user

        def require_verifier_or_issuer_dep(request: Request) -> UserSession:
            user = get_current_user(request, self.session_manager)
            if not user:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Autenticazione richiesta")
            if user.role not in ["issuer", "verifier"]:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Accesso riservato alle università")
            return user

        def require_student_dep(request: Request) -> UserSession:
            user = get_current_user(request, self.session_manager)
            if not user:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Autenticazione richiesta")
            if user.role != "studente":
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Accesso riservato agli studenti")
            return user

        return {
            'get_current_user': get_current_user_dep,
            'require_auth': require_auth_dep,
            'require_issuer': require_issuer_dep,
            'require_verifier_or_issuer': require_verifier_or_issuer_dep,
            'require_student': require_student_dep
        }

    def _initialize_system_components(self) -> None:
        """Inizializza i componenti principali del sistema."""
        self.logger.info("Inizializzazione componenti di sistema...")

        if not MODULES_AVAILABLE:
            self.logger.warning("I moduli principali non sono disponibili - esecuzione in modalità demo")
            return

        try:
            current_dir = Path.cwd()
            self.logger.info(f"Directory di lavoro corrente: {current_dir}")

            possible_cert_paths = [
                "certificates/issued/university_FR_RENNES01_1001.pem",
                "./certificates/issued/university_FR_RENNES01_1001.pem",
            ]

            possible_key_paths = [
                "keys/universite_rennes_private.pem",
                "./keys/universite_rennes_private.pem",
            ]

            cert_path = None
            key_path = None

            for path in possible_cert_paths:
                if Path(path).exists():
                    cert_path = path
                    self.logger.info(f"ertificato trovato in: {cert_path}")
                    break

            for path in possible_key_paths:
                if Path(path).exists():
                    key_path = path
                    self.logger.info(f"Chiave privata trovata in: {key_path}")
                    break

            if not cert_path or not key_path:
                self.logger.error("File richiesti non trovati:")
                self.logger.error(f"   Certificato: {cert_path or 'NON TROVATO'}")
                self.logger.error(f"   Chiave privata: {key_path or 'NON TROVATA'}")
                self.logger.error("   Eseguire prima certificate_authority.py per generare i certificati")
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

            self.logger.info("Creazione di AcademicCredentialIssuer...")
            self.issuer = AcademicCredentialIssuer(config=issuer_config)
            self.logger.info("Emittente inizializzato con successo")

        except Exception as e:
            self.logger.error(f"Errore durante l'inizializzazione dei componenti di sistema: {e}", exc_info=True)
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
        """Funzione di aiuto per chiamare le API sicure."""
        url = f"{self.config.secure_server_url}{endpoint}"
        headers = {"Authorization": f"Bearer {self.config.secure_server_api_key}"}

        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()

    def _get_student_wallet(self, user: UserSession) -> AcademicStudentWallet:
        """Funzione di aiuto per ottenere o creare il portafoglio di uno studente."""
        if not user or user.role != "studente":
            return None

        common_name = user.user_id
        if common_name.startswith("studente_"):
            common_name = common_name[len("studente_"):].replace('_', ' ').title()
        else:
            common_name = common_name.replace('_', ' ').title()

        student_id = "0622702628"  # ID preimpostato per l'utente demo

        wallet_name = f"studente_{common_name.replace(' ', '_').lower()}_wallet"
        wallet_path = self.wallets_dir / wallet_name

        config = WalletConfiguration(
            wallet_name=wallet_name,
            storage_path=str(wallet_path)
        )
        wallet = AcademicStudentWallet(config)

        if not wallet.wallet_file.exists():
            self.logger.info(f"🔧 Creazione portafoglio per {common_name}...")

            wallet.create_wallet(
                password="Unisa2025",
                student_common_name="Mario Rossi",  
                student_id=student_id
            )
        if wallet.status == WalletStatus.LOCKED:
            wallet.unlock_wallet("Unisa2025")

        return wallet
    
    def _get_wallet_credentials_with_ids(self, wallet) -> List[Dict]:
        """Ottiene le credenziali del wallet con i loro ID reali."""
        credentials = []
        wallet_creds = wallet.list_credentials()
        
        for cred_info in wallet_creds:
            try:
                # Ottieni la credenziale completa per estrarre l'ID reale
                storage_id = cred_info['storage_id']
                full_cred = wallet.get_credential(storage_id)
                
                if full_cred and full_cred.credential:
                    # Estrai l'ID reale dalla credenziale
                    real_credential_id = str(full_cred.credential.metadata.credential_id)
                    
                    credentials.append({
                        'storage_id': storage_id,
                        'credential_id': real_credential_id,  # ID reale della credenziale
                        'issuer': cred_info['issuer'],
                        'issue_date': cred_info['issued_at'],
                        'total_courses': cred_info['total_courses'],
                        'status': cred_info['status']
                    })
                else:
                    # Fallback se non riusciamo a ottenere la credenziale completa
                    credentials.append({
                        'storage_id': storage_id,
                        'credential_id': storage_id,  # Usa storage_id come fallback
                        'issuer': cred_info['issuer'],
                        'issue_date': cred_info['issued_at'],
                        'total_courses': cred_info['total_courses'],
                        'status': cred_info['status']
                    })
                    
            except Exception as e:
                self.logger.warning(f"Errore nell'ottenere l'ID della credenziale {cred_info.get('storage_id', 'unknown')}: {e}")
                # Aggiungi comunque la credenziale con le info disponibili
                credentials.append({
                    'storage_id': cred_info.get('storage_id', 'unknown'),
                    'credential_id': cred_info.get('storage_id', 'unknown'),
                    'issuer': cred_info.get('issuer', 'Sconosciuto'),
                    'issue_date': cred_info.get('issued_at', 'Sconosciuto'),
                    'total_courses': cred_info.get('total_courses', 0),
                    'status': cred_info.get('status', 'Sconosciuto')
                })
        
        return credentials

    def _setup_routes(self) -> None:
        """Configura tutte le rotte dell'applicazione."""

        # Route principale con redirect appropriato
        @self.app.get("/", response_class=HTMLResponse)
        async def home(request: Request):
            user = self.auth_deps['get_current_user'](request)
            if user:
                if user.role == 'studente':
                    return RedirectResponse(url="/wallet", status_code=HTTP_302_FOUND)
                else:
                    return RedirectResponse(url="/dashboard", status_code=HTTP_302_FOUND)
            return self.templates.TemplateResponse("home.html", {"request": request, "title": "Home"})

        # Aggiunta dell'endpoint GET per la pagina di login
        @self.app.get("/login", response_class=HTMLResponse)
        async def login_page(request: Request):
            """Mostra la pagina di login."""
            return self.templates.TemplateResponse("login.html", {"request": request, "title": "Login"})

        # Autenticazione
        @self.app.post("/login")
        async def login(request: Request, username: str = Form(...), password: str = Form(...)):
            """Gestisce il login dell'utente."""
            try:
                user_info = AuthenticationService.authenticate_user(username, password)
                if user_info:
                    session_id = self.session_manager.create_session(user_info, username)
                    request.session["session_id"] = session_id

                    redirect_url = "/wallet" if user_info["role"] == "studente" else "/dashboard"
                    self.logger.info(f"Login riuscito per {username} (ruolo: {user_info['role']})")
                    return RedirectResponse(url=redirect_url, status_code=HTTP_302_FOUND)

                return self.templates.TemplateResponse("login.html", {
                    "request": request, "error": "Credenziali non valide", "title": "Login"
                })
            except Exception as e:
                self.logger.error(f"Errore di login: {e}")
                return self.templates.TemplateResponse("login.html", {
                    "request": request, "error": "Errore di sistema. Riprova più tardi.", "title": "Login"
                })
            
        @self.app.get("/credentials/download", response_class=FileResponse)
        async def download_credential(
            request: Request,
            file_path: str = Query(..., description="Il percorso del file della credenziale da scaricare")
        ):
            """Endpoint sicuro per scaricare un file di credenziale."""
            user = self.auth_deps['require_issuer'](request)

            # --- Controllo di sicurezza per prevenire Path Traversal ---
            base_path = Path.cwd().resolve()
            allowed_dirs = [
                base_path / "src" / "credentials",
                base_path / "credentials"
            ]
            requested_path = Path(file_path).resolve()
            
            is_path_safe = any(requested_path.is_relative_to(allowed_dir) for allowed_dir in allowed_dirs)

            if not is_path_safe:
                self.logger.error(f"Tentativo di accesso non consentito al percorso: {requested_path}")
                raise HTTPException(status_code=403, detail="Accesso al percorso non consentito")

            if not requested_path.is_file():
                raise HTTPException(status_code=404, detail="File non trovato")

            return FileResponse(
                path=str(requested_path),
                media_type='application/json',
                filename=requested_path.name
            )

        @self.app.get("/logout")
        async def logout(request: Request):
            """Esegue il logout dell'utente."""
            session_id = request.session.get("session_id")
            if session_id:
                self.session_manager.destroy_session(session_id)
            request.session.clear()
            return RedirectResponse(url="/", status_code=HTTP_302_FOUND)

        # Emissione credenziali - solo per issuer
        @self.app.get("/credentials/issue", response_class=HTMLResponse)
        async def issue_credential_page(request: Request):
            user = self.auth_deps['require_issuer'](request)
            return self.templates.TemplateResponse("issue_credential.html", {
                "request": request, "user": user, "title": "Emetti nuova credenziale"
            })

        @self.app.post("/credentials/issue")
        async def handle_issue_credential(
            request: Request, 
            student_name: str = Form(...), 
            student_id: str = Form(...), 
            credential_type: str = Form(...),
            study_period_start: str = Form(...), 
            study_period_end: str = Form(...),
            callback_url: Optional[str] = Form(None), 
            course_name: List[str] = Form([]),
            course_cfu: List[str] = Form([]), 
            course_grade: List[str] = Form([]),
            course_date: List[str] = Form([])
        ):
            """
            Gestisce l'emissione di una nuova credenziale.
            """
            user = self.auth_deps['require_issuer'](request)
            
            self.logger.info(f"Richiesta di emissione credenziale ricevuta per lo studente: {student_name}")

            try:
                if not self.issuer:
                    self.logger.error("Servizio di emissione non inizializzato")
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Servizio di emissione non disponibile"
                    )

                self.logger.info("Preparazione dati studente...")
                crypto_utils = CryptoUtils()

                name_parts = student_name.strip().split()
                first_name = name_parts[0] if name_parts else "Sconosciuto"
                last_name = name_parts[-1] if len(name_parts) > 1 else "Studente"

                surname_salt = crypto_utils.generate_salt()
                name_salt = crypto_utils.generate_salt()
                birth_date_salt = crypto_utils.generate_salt()
                student_id_salt = crypto_utils.generate_salt()

                student_info = PersonalInfo(
                    surname_hash=crypto_utils.hash_with_salt(last_name, surname_salt),
                    surname_salt=surname_salt.hex(),
                    name_hash=crypto_utils.hash_with_salt(first_name, name_salt),
                    name_salt=name_salt.hex(),
                    birth_date_hash=crypto_utils.hash_with_salt("1990-01-01", birth_date_salt), 
                    birth_date_salt=birth_date_salt.hex(),
                    student_id_hash=crypto_utils.hash_with_salt(student_id, student_id_salt),
                    student_id_salt=student_id_salt.hex(),
                    pseudonym=f"studente_{student_name.lower().replace(' ', '_')}"
                )


                # Preparazione periodo di studio
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
                except Exception as e:
                    raise ValueError(f"Date non valide: {e}")

                host_university = self.issuer.config.university_info
                study_program = StudyProgram(
                    name="Computer Science Exchange Program",
                    isced_code="0613",
                    eqf_level=EQFLevel.LEVEL_7,
                    program_type="Master's Degree Exchange",
                    field_of_study="Computer Science"
                )

                # Preparazione corsi
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
                        except Exception as e:
                            raise ValueError(f"Errore nel corso {course_name[i]}: {e}")

                if not courses:
                    raise ValueError("È necessario specificare almeno un corso")

                # Creazione e elaborazione richiesta
                request_id = self.issuer.create_issuance_request(
                    student_info=student_info,
                    study_period=study_period,
                    host_university=host_university,
                    study_program=study_program,
                    courses=courses,
                    requested_by=user.user_id,
                    notes=f"Tipo di credenziale: {credential_type}"
                )

                issuance_result = self.issuer.process_issuance_request(request_id)

                if not issuance_result.success:
                    error_msg = "; ".join(issuance_result.errors)
                    raise ValueError(f"Emissione fallita: {error_msg}")

                credential = issuance_result.credential
                credential_id_str = str(credential.metadata.credential_id)

                # Gestione callback
                callback_success_message = ""
                if callback_url and callback_url.strip():
                    try:
                        credential_dict = credential.to_dict()
                        
                        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
                            response = await client.post(
                                callback_url,
                                json=credential_dict,
                                headers={
                                    "Content-Type": "application/json",
                                    "User-Agent": "AcademicCredentials-Dashboard/1.0"
                                }
                            )
                            
                            if response.is_success:
                                callback_success_message = f" La credenziale è stata inviata con successo a {callback_url}"
                            else:
                                callback_success_message = f" ATTENZIONE: Errore nell'invio a {callback_url} (HTTP {response.status_code})"
                                
                    except Exception as callback_error:
                        callback_success_message = f" ATTENZIONE: Errore durante l'invio a {callback_url}: {str(callback_error)}"

                # Salva credenziale su file
                import re
                safe_student_name = re.sub(r'[^\w\s-]', '', student_name).strip().replace(' ', '_')
                output_dir = Path(f"src/credentials/{user.user_id}/{safe_student_name}/")
                output_dir.mkdir(parents=True, exist_ok=True)
                output_path = output_dir / f"{credential_id_str}.json"

                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(credential.to_json())

                result_data = {
                    "success": True,
                    "message": f"Credenziale emessa con successo!{callback_success_message}",
                    "credential_id": credential_id_str,
                    "file_path": str(output_path),
                    "issued_at": credential.metadata.issued_at.isoformat(),
                    "total_courses": len(courses),
                    "total_ects": sum(c.ects_credits for c in courses)
                }

                return JSONResponse(result_data)

            except ValueError as e:
                return JSONResponse(
                    {"success": False, "message": f"Errore nei dati: {str(e)}"},
                    status_code=400
                )
            except Exception as e:
                self.logger.error(f"Errore critico durante l'emissione: {e}", exc_info=True)
                return JSONResponse(
                    {"success": False, "message": f"Errore interno del server: {str(e)}"},
                    status_code=500
                )

        # Verifica credenziali - per issuer e verifier
        @self.app.get("/verification", response_class=HTMLResponse)
        async def verification_page(request: Request):
            user = self.auth_deps['require_verifier_or_issuer'](request)
            return self.templates.TemplateResponse("verification.html", {
                "request": request, "user": user, "title": "Verifica credenziali"
            })

        @self.app.post("/verification/full-verify")
        async def handle_full_verification(request: Request):
            """Gestisce la verifica completa di una presentazione selettiva."""
            user = self.auth_deps['require_verifier_or_issuer'](request)
            
            try:
                self.logger.info(f"Richiesta di verifica completa da {user.user_id}")

                body = await request.json()
                presentation_data = body.get("presentation_data")
                student_public_key = body.get("student_public_key")
                purpose = body.get("purpose", "verification")
                check_ocsp = body.get("check_ocsp", False)

                if not presentation_data or not student_public_key:
                    return JSONResponse(
                        {"success": False, "message": "Dati della presentazione e chiave pubblica richiesti"},
                        status_code=400
                    )

                verification_report = await self.verification_service.verify_presentation_complete(
                    presentation_data, student_public_key, purpose, check_ocsp
                )

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
                self.logger.error(f"Errore nella verifica completa: {e}")
                return JSONResponse(
                    {"success": False, "message": f"Errore interno: {str(e)}"},
                    status_code=500
                )

        # Verifica blockchain per studenti
        @self.app.get("/verification/student", response_class=HTMLResponse)
        async def handle_student_blockchain_verify(request: Request):
            user = self.auth_deps['require_student'](request)
            body = await request.json()
            credential_id = body.get("credential_id")
            
            if not credential_id:
                return JSONResponse(
                    {"success": False, "message": "ID credenziale richiesto"}, 
                    status_code=400
                )
            
            try:
                async with httpx.AsyncClient(verify=False) as client:
                    response = await client.post(
                        f"{self.config.secure_server_url}/api/v1/blockchain/credentials/verify",
                        headers={"Authorization": f"Bearer student_token"},
                        json={"credential_id": credential_id},
                        timeout=10.0
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        return JSONResponse({"success": True, "blockchain_status": result["blockchain_status"]})
                    else:
                        return JSONResponse(
                            {"success": False, "message": "Errore nella verifica blockchain"},
                            status_code=502
                        )
            except Exception as e:
                return JSONResponse(
                    {"success": False, "message": f"Errore: {str(e)}"},
                    status_code=500
                )

        # Richiesta credenziali per studenti
        @self.app.get("/student/request", response_class=HTMLResponse)
        async def student_request_page(request: Request):
            user = self.auth_deps['require_student'](request)
            return self.templates.TemplateResponse("student_request.html", {
                "request": request, "user": user, "title": "Richiedi credenziale"
            })

        @self.app.post("/request_credential")
        async def handle_credential_request(request: Request):
            """Gestisce la richiesta di una credenziale a un'università esterna."""
            user = self.auth_deps['require_student'](request)
            
            try:
                data = await request.json()
                university = data.get('university')
                purpose = data.get('purpose', '')

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
                wallet = self._get_student_wallet(user)
                student_id = "0622702628"

                payload = {
                    "student_name": "Mario Rossi",
                    "student_id": student_id,
                    "purpose": purpose,
                    "requested_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
                }

                async with httpx.AsyncClient(verify=False) as client:
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
                            "message": f"Errore dall'università: {response.text}",
                            "status_code": response.status_code
                        }, status_code=502)

            except Exception as e:
                return JSONResponse(
                    {"success": False, "message": f"Errore interno: {str(e)}"},
                    status_code=500
                )

        # Dashboard per università (issuer e verifier)
        @self.app.get("/dashboard", response_class=HTMLResponse)
        async def dashboard(request: Request):
            user = self.auth_deps['require_verifier_or_issuer'](request)
            
            stats = {
                "total_credentials_issued": self.issuer.stats.get('credentials_issued', 0) if self.issuer else 0,
                "total_credentials_verified": 0,
                "pending_verifications": 0,
                "success_rate": 100.0,
                "last_updated": datetime.datetime.now(datetime.timezone.utc)
            }
            message = request.query_params.get("message")

            return self.templates.TemplateResponse("dashboard.html", {
                "request": request, "user": user, "stats": stats, "title": "Dashboard", "message": message
            })

        # Gestione credenziali - solo per issuer
        @self.app.get("/credentials", response_class=HTMLResponse)
        async def credentials_page(request: Request):
            user = self.auth_deps['require_issuer'](request)
            credentials = self._load_credentials_for_display()
            return self.templates.TemplateResponse("credentials.html", {
                "request": request, "user": user, "title": "Gestisci credenziali", "credentials": credentials
            })
        
        # Route di test per verificare l'autenticazione
        @self.app.get("/test/auth")
        async def test_auth(request: Request):
            """Route di test per verificare l'autenticazione."""
            try:
                user = self.auth_deps['get_current_user'](request)
                if user:
                    return JSONResponse({
                        "authenticated": True,
                        "user_id": user.user_id,
                        "role": user.role,
                        "permissions": user.permissions,
                        "university": user.university_name
                    })
                else:
                    return JSONResponse({
                        "authenticated": False,
                        "message": "Nessuna sessione attiva"
                    })
            except Exception as e:
                return JSONResponse({
                    "error": str(e),
                    "authenticated": False
                })

        # Wallet studente
        @self.app.get("/wallet", response_class=HTMLResponse)
        async def wallet_page(request: Request):
            user = self.auth_deps['require_student'](request)
            wallet = self._get_student_wallet(user)
            
            # Metodo per ottenere le credenziali con ID reali
            credentials = self._get_wallet_credentials_with_ids(wallet)

            return self.templates.TemplateResponse("student_wallet.html", {
                "request": request, "user": user, "title": "Il mio wallet", "credentials": credentials
            })

        @self.app.get("/credentials/{storage_id}", response_class=JSONResponse)
        async def get_credential_details(
            storage_id: str, 
            user: UserSession = Depends(self.auth_deps['require_auth'])
        ):
            """Ottiene i dettagli di una specifica credenziale."""
            wallet = self._get_student_wallet(user)
            cred = wallet.get_credential(storage_id)

            if not cred:
                raise HTTPException(status_code=404, detail="Credenziale non trovata")

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
        async def create_presentation(request: Request):
            """Crea una nuova presentazione da credenziali selezionate con divulgazione selettiva."""
            user = self.auth_deps['require_student'](request)
            
            try:
                body = await request.json()

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
                        {"success": False, "message": "Portafoglio non disponibile o bloccato"},
                        status_code=500
                    )

                if not MODULES_AVAILABLE:
                    return JSONResponse(
                        {"success": False, "message": "Moduli del portafoglio non disponibili"},
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

                credential_selections = []
                for storage_id in body.get('credentials'):
                    wallet_cred = wallet.get_credential(storage_id)
                    if not wallet_cred:
                        return JSONResponse(
                            {"success": False, "message": f"Credenziale {storage_id} non trovata nel portafoglio"},
                            status_code=400
                        )

                    selection = {
                        'storage_id': storage_id,
                        'disclosure_level': DisclosureLevel.CUSTOM,
                        'custom_attributes': selected_attributes
                    }
                    credential_selections.append(selection)

                presentation_ids = presentation_manager.create_presentation(
                    purpose=body.get('purpose'),
                    credential_selections=credential_selections,
                    recipient=body.get('recipient'),
                    expires_hours=72
                )

                presentations_details = []

                for presentation_id in presentation_ids:
                    sign_success = presentation_manager.sign_presentation(presentation_id)
                    if not sign_success:
                        return JSONResponse(
                            {"success": False, "message": f"Errore durante la firma della presentazione {presentation_id}"},
                            status_code=500
                        )

                    export_dir = wallet.wallet_dir / "presentations"
                    export_dir.mkdir(exist_ok=True)
                    output_path = export_dir / f"{presentation_id}.json"

                    export_success = presentation_manager.export_presentation(
                        presentation_id,
                        str(output_path),
                        PresentationFormat.SIGNED_JSON
                    )

                    if not export_success:
                        return JSONResponse(
                            {"success": False, "message": f"Errore durante l'esportazione della presentazione {presentation_id}"},
                            status_code=500
                        )

                    presentation = presentation_manager.get_presentation(presentation_id)
                    if not presentation:
                        return JSONResponse(
                            {"success": False, "message": f"Errore: presentazione {presentation_id} non trovata dopo la creazione"},
                            status_code=500
                        )

                    summary = presentation.get_summary()
                    presentations_details.append({
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
                    })

                response_data = {
                    "success": True,
                    "message": "Presentazioni verificabili create con successo",
                    "presentations": presentations_details
                }

                return self._create_json_response(response_data)

            except ImportError as e:
                self.logger.error(f"Errore di importazione nella creazione della presentazione: {e}")
                return JSONResponse(
                    {"success": False, "message": "Moduli del portafoglio non disponibili"},
                    status_code=503
                )
            except Exception as e:
                self.logger.error(f"Errore nella creazione della presentazione: {e}", exc_info=True)
                return JSONResponse(
                    {"success": False, "message": f"Errore interno: {str(e)}"},
                    status_code=500
                )

        @self.app.post("/wallet/import-credential", response_class=JSONResponse)
        async def import_credential(
            request_body: CredentialImportRequest,
            user: UserSession = Depends(self.auth_deps['require_student'])
        ):
            """Endpoint per importare una credenziale da un file JSON nel wallet dello studente."""
            self.logger.info(f"Richiesta di importazione credenziale per l'utente: {user.user_id}")
            
            try:
                wallet = self._get_student_wallet(user)
                if not wallet or wallet.status != WalletStatus.UNLOCKED:
                    return JSONResponse(
                        {"success": False, "message": "Wallet non disponibile o bloccato."},
                        status_code=500
                    )
                
                # La funzione ora restituisce un tuple (storage_id, error_message)
                storage_id, error_message = wallet.add_credential_from_json(
                    request_body.credential_json,
                    tags=["importata"]
                )
                
                if storage_id:
                    return JSONResponse({
                        "success": True,
                        "message": "Credenziale importata con successo nel tuo wallet!",
                        "storage_id": storage_id
                    })
                else:
                    # Usa il messaggio di errore specifico fornito dal wallet
                    return JSONResponse(
                        {"success": False, "message": error_message or "Impossibile importare la credenziale per un motivo sconosciuto."},
                        status_code=400
                    )
            
            except Exception as e:
                self.logger.error(f"Errore critico durante l'importazione: {e}", exc_info=True)
                return JSONResponse(
                    {"success": False, "message": f"Errore interno del server: {str(e)}"},
                    status_code=500
                )

        @self.app.get("/presentations/{presentation_id}/download")
        async def download_presentation(
            presentation_id: str,
            request: Request
        ):        
            """Permette di scaricare un file di presentazione."""
            user = self.auth_deps['require_student'](request)
            
            try:
                wallet = self._get_student_wallet(user)
                file_path = wallet.wallet_dir / "presentations" / f"{presentation_id}.json"

                if not file_path.exists():
                    raise HTTPException(status_code=404, detail="Presentazione non trovata")

                return FileResponse(
                    file_path,
                    filename=f"presentation_{presentation_id[:8]}.json",
                    media_type='application/json'
                )

            except HTTPException:
                raise
            except Exception as e:
                self.logger.error(f"Errore durante il download della presentazione: {e}")
                raise HTTPException(status_code=500, detail="Errore durante il download")

        # Endpoint di debug
        @self.app.get("/debug/directories")
        async def debug_directories(request: Request):
            """Endpoint di debug per controllare le directory."""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role not in ["issuer", "admin"]:
                raise HTTPException(status_code=403, detail="Accesso negato")
            
            current_dir = Path.cwd()
            debug_info = {
                "current_directory": str(current_dir),
                "credentials_paths": {
                    "src/credentials": {
                        "exists": (current_dir / "src" / "credentials").exists(),
                        "path": str(current_dir / "src" / "credentials"),
                        "files": []
                    },
                    "credentials": {
                        "exists": (current_dir / "credentials").exists(), 
                        "path": str(current_dir / "credentials"),
                        "files": []
                    }
                }
            }
            
            for base_name, info in debug_info["credentials_paths"].items():
                base_path = Path(info["path"])
                if base_path.exists():
                    info["files"] = [str(f) for f in base_path.rglob("*.json")]
            
            return self._create_json_response(debug_info)
        
    def _load_credentials_for_display(self):
        """Carica le credenziali per la visualizzazione nella dashboard issuer."""
        credentials = []
        try:
            current_dir = Path.cwd()
            possible_base_dirs = [
                current_dir / "src" / "credentials",
                current_dir / "credentials", 
                Path("./src/credentials"),
                Path("./credentials")
            ]
            
            credentials_base_dir = None
            for base_dir in possible_base_dirs:
                if base_dir.exists():
                    credentials_base_dir = base_dir
                    break
            
            if not credentials_base_dir:
                credentials_base_dir = current_dir / "src" / "credentials"
                credentials_base_dir.mkdir(parents=True, exist_ok=True)

            credential_files = []
            if credentials_base_dir.exists():
                for json_file in credentials_base_dir.rglob("*.json"):
                    if json_file.is_file():
                        credential_files.append(json_file)
            
            for credential_file in credential_files:
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
                                'total_courses': summary['total_courses'],
                                'total_ects': summary['total_ects'],
                                'file_path': str(credential_file)
                            })
                        else:
                            credential_data = json.load(f)
                            metadata = credential_data.get('metadata', {})
                            issuer = credential_data.get('issuer', {})
                            courses = credential_data.get('courses', [])
                            
                            credentials.append({
                                'credential_id': str(metadata.get('credential_id', credential_file.stem)),
                                'student_name': credential_data.get('subject', {}).get('pseudonym', 'Studente sconosciuto'),
                                'issued_at': metadata.get('issued_at', '2024-01-01T00:00:00')[:19],
                                'issued_by': issuer.get('name', 'Università sconosciuta'),
                                'total_courses': len(courses),
                                'total_ects': sum(course.get('ects_credits', 0) for course in courses),
                                'file_path': str(credential_file)
                            })
                            
                except Exception as e:
                    self.logger.warning(f"Errore nel caricamento della credenziale {credential_file}: {e}")
                    continue

            credentials.sort(key=lambda x: x['issued_at'], reverse=True)

        except Exception as e:
            self.logger.error(f"Errore nel caricamento delle credenziali: {e}")

        return credentials


# =============================================================================
# PUNTO DI INGRESSO DELL'APPLICAZIONE
# =============================================================================

_dashboard_instance = None

def get_dashboard_app() -> FastAPI:
    """Funzione factory per ottenere l'istanza dell'applicazione."""
    global _dashboard_instance
    if _dashboard_instance is None:
        _dashboard_instance = AcademicCredentialsDashboard()
    return _dashboard_instance.app

app = get_dashboard_app()

if __name__ == "__main__":
    print("Avvio della Dashboard Credenziali Accademiche in modalità standalone...")
    dashboard = AcademicCredentialsDashboard()
    dashboard.run()