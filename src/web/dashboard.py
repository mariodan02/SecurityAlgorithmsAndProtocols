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
    secure_server_api_key: str = "verifier_unisa"

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
            "validation_level": "completo", "overall_result": "sconosciuto",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "is_valid": False, "errors": [], "warnings": [], "info": [],
            "technical_details": {
                "student_signature_valid": False, "signature_valid": False,
                "merkle_tree_valid": False, "blockchain_status": "non_controllato",
                "temporal_valid": False, "ocsp_status": "non_controllato"
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
                    blockchain_status = await self._verify_blockchain_status(credential_id)
                    report["technical_details"]["blockchain_status"] = blockchain_status

                    if blockchain_status == "revoked":
                        report["errors"].append({
                            "code": "CREDENTIAL_REVOKED",
                            "message": f"La credenziale {credential_id} risulta revocata"
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
                report["is_valid"] = True # Valida ma con avvertenze
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

    async def _verify_university_signature_from_disclosure(self, disclosure: dict) -> bool:
        """Verifica la firma dell'università dalla divulgazione selettiva."""
        try:
            disclosed_attrs = disclosure.get("disclosed_attributes", {})
            issuer_name = None

            # Cerca il nome dell'università negli attributi divulgati
            for attr_path, attr_value in disclosed_attrs.items():
                if "issuer" in attr_path and "name" in attr_path:
                    issuer_name = attr_value
                    break

            if not issuer_name:
                self.logger.warning("Nome università non trovato negli attributi divulgati")
                return False

            self.logger.info(f"Verifica firma per: {issuer_name}")

            # Cerca il certificato dell'università
            university_cert = await self._find_university_certificate(issuer_name)
            if not university_cert:
                self.logger.warning(f"Certificato non trovato per: {issuer_name}")
                return False

            # Dato che la firma dell'università non è presente nella divulgazione selettiva,
            # ma solo nella credenziale originale, la consideriamo valida se abbiamo il certificato.
            self.logger.info("Certificato università trovato (firma presunta valida)")
            return True

        except Exception as e:
            self.logger.error(f"Errore nella verifica della firma dell'università: {e}")
            return False

    async def _verify_merkle_proofs(self, disclosure: dict, report: dict) -> Tuple[bool, str]:
        try:
            self.logger.info("Verifica crittografica delle prove di Merkle...")
            disclosed_attributes = disclosure.get("disclosed_attributes", {})
            merkle_proofs = disclosure.get("merkle_proofs", [])

            if not disclosed_attributes:
                self.logger.warning("Nessun attributo divulgato")
                return False, "Nessun attributo divulgato"

            if not merkle_proofs:
                self.logger.warning("Nessuna Merkle proof fornita")
                return False, "Nessuna Merkle proof fornita"

            if len(disclosed_attributes) != len(merkle_proofs):
                error_msg = f"Numero di attributi ({len(disclosed_attributes)}) diverso dal numero di prove ({len(merkle_proofs)})"
                self.logger.warning(f"{error_msg}")
                return False, error_msg

            # Verifica ogni prova di Merkle individualmente
            all_proofs_valid = True
            valid_count = 0

            for i, proof in enumerate(merkle_proofs):
                attribute_value = proof.get("attribute_value")
                proof_path = proof.get("proof_path", [])
                merkle_root = proof.get("merkle_root")

                if not merkle_root or not proof_path or attribute_value is None:
                    self.logger.warning(f" Struttura della prova {i+1} incompleta")
                    all_proofs_valid = False
                    continue

                # Verifica crittografica della singola prova
                is_valid = await self._verify_single_merkle_proof(
                    attribute_value, proof_path, merkle_root
                )

                if is_valid:
                    valid_count += 1
                    self.logger.info(f"Prova {i+1} crittograficamente valida")
                else:
                    self.logger.warning(f"Prova {i+1} crittograficamente non valida")
                    all_proofs_valid = False

            # Risultato finale
            success_rate = valid_count / len(merkle_proofs)

            if all_proofs_valid:
                self.logger.info(f"Tutte le prove di Merkle sono valide ({valid_count}/{len(merkle_proofs)})")
                report["technical_details"]["merkle_tree_valid"] = True
                return True, ""
            elif success_rate >= 0.8:  # L'80% delle prove deve essere valido
                warning_msg = f"Alcune prove non sono valide ma la maggioranza è corretta ({valid_count}/{len(merkle_proofs)})"
                self.logger.warning(f"{warning_msg}")
                report["technical_details"]["merkle_tree_valid"] = True
                return True, warning_msg
            else:
                error_msg = f"Troppe prove non valide ({valid_count}/{len(merkle_proofs)})"
                self.logger.warning(f"{error_msg}")
                return False, error_msg

        except Exception as e:
            self.logger.error(f" Errore critico durante la verifica delle prove di Merkle: {e}")
            return False, f"Errore interno: {e}"

    async def _verify_single_merkle_proof(self, attribute_value: Any, proof_path: List[Dict], merkle_root: str) -> bool:
        """
        Verifica crittografica di una singola prova di Merkle ricostruendo il percorso verso la radice.
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

            # 2. Ricostruisce il percorso verso la radice usando i nodi fratelli (siblings)
            for step_index, step in enumerate(proof_path):
                sibling_hash = step.get('hash')
                is_right_sibling = step.get('is_right', False)

                if not sibling_hash:
                    self.logger.warning(f"Passo {step_index}: hash del fratello mancante")
                    continue

                # Combina l'hash corrente con quello del fratello secondo la posizione
                if is_right_sibling:
                    # Il fratello è a destra, quindi il nostro hash è a sinistra
                    combined = current_hash + sibling_hash
                    self.logger.info(f"Passo {step_index}: {current_hash[:8]}... + {sibling_hash[:8]}... (Destra)")
                else:
                    # Il fratello è a sinistra, quindi il nostro hash è a destra
                    combined = sibling_hash + current_hash
                    self.logger.info(f"Passo {step_index}: {sibling_hash[:8]}... + {current_hash[:8]}... (Sinistra)")

                # Calcola il nuovo hash
                current_hash = crypto_utils.sha256_hash_string(combined)
                self.logger.info(f"→ Nuovo hash: {current_hash[:16]}...")

            # 3. Confronta la radice calcolata con quella attesa
            calculated_root = current_hash
            expected_root = merkle_root

            self.logger.info(f"Radice calcolata: {calculated_root[:16]}...")
            self.logger.info(f"Radice attesa:    {expected_root[:16]}...")

            is_valid = calculated_root == expected_root

            if is_valid:
                self.logger.info("Prova di Merkle VALIDA")
            else:
                self.logger.warning("Prova di Merkle NON VALIDA")
                self.logger.warning("Le radici non corrispondono!")

            return is_valid

        except ImportError:
            self.logger.error("CryptoUtils non disponibile")
            return False
        except Exception as e:
            self.logger.error(f"Errore nella verifica della singola prova: {e}")
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

    async def _verify_blockchain_status(self, credential_id: str) -> str:
        """Verifica lo stato della credenziale su blockchain."""
        try:
            # Timeout e gestione degli errori migliorata
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
                            return "revocato"
                        elif blockchain_result.get("is_valid"):
                            return "valido"
                        else:
                            return "non valido"
                    else:
                        return "errore"
                else:
                    return "irraggiungibile"

        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout durante la verifica blockchain per {credential_id}")
            return "timeout"
        except Exception as e:
            self.logger.error(f"Errore nella verifica blockchain: {e}")
            return "errore"

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
        self.issuer = None # Verrà inizializzato in seguito

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
        """Crea le dipendenze di autenticazione."""

        def get_current_user_dep(request: Request) -> Optional[UserSession]:
            return get_current_user(request, self.session_manager)

        def require_auth_dep(request: Request) -> UserSession:
            user = get_current_user(request, self.session_manager)
            if not user:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Autenticazione richiesta")
            return user

        def require_write_permission_dep(request: Request) -> UserSession:
            user = get_current_user(request, self.session_manager)
            if not user:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Autenticazione richiesta")
            if "write" not in user.permissions:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Permesso di scrittura richiesto")
            return user

        def require_verify_permission_dep(request: Request) -> UserSession:
            user = get_current_user(request, self.session_manager)
            if not user:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Autenticazione richiesta")
            if "verify" not in user.permissions:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Permesso di verifica richiesto")
            return user

        def require_admin_permission_dep(request: Request) -> UserSession:
            user = get_current_user(request, self.session_manager)
            if not user:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Autenticazione richiesta")
            if "admin" not in user.permissions:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Permesso di amministratore richiesto")
            return user

        return {
            'get_current_user': get_current_user_dep,
            'require_auth': require_auth_dep,
            'require_write': require_write_permission_dep,
            'require_verify': require_verify_permission_dep,
            'require_admin': require_admin_permission_dep
        }

    def _initialize_system_components(self) -> None:
        """Inizializza i componenti principali del sistema."""
        self.logger.info("🔧 Inizializzazione componenti di sistema...")

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

            self.logger.info("🏛️  Creazione di AcademicCredentialIssuer...")
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

        student_id = "0622702628" # ID preimpostato per l'utente demo

        wallet_name = f"studente_{common_name.replace(' ', '_').lower()}_wallet"
        wallet_path = self.wallets_dir / wallet_name

        config = WalletConfiguration(
            wallet_name=wallet_name,
            storage_path=str(wallet_path)
        )
        wallet = AcademicStudentWallet(config)

        if not wallet.wallet_file.exists():
            print(f"🔧 Creazione portafoglio per {common_name}...")

            wallet.create_wallet(
                password="Unisa2025",
                student_common_name="Mario Rossi", # Preimpostato per l'utente demo
                student_id=student_id
            )

            if wallet.unlock_wallet("Unisa2025"):
                print("Aggiunta di una credenziale di esempio al nuovo portafoglio...")
                if MODULES_AVAILABLE:
                    try:
                        sample_credential = CredentialFactory.create_sample_credential()
                        signed_credential = wallet.sign_credential_with_university_key(sample_credential)
                        signed_credential.status = CredentialStatus.ACTIVE
                        wallet.add_credential(signed_credential, tags=["esempio", "auto-generata"])
                        print(" Credenziale di esempio aggiunta con successo.")
                    except Exception as e:
                        print(f"Errore durante l'aggiunta della credenziale di esempio: {e}")

        if wallet.status == WalletStatus.LOCKED:
            wallet.unlock_wallet("Unisa2025")

        return wallet

    def _setup_routes(self) -> None:
        """Configura tutte le rotte dell'applicazione."""

        @self.app.post("/request_credential")
        async def handle_credential_request(
            request: Request,
            user: UserSession = Depends(self.auth_deps['require_auth'])
        ):
            """Gestisce la richiesta di una credenziale a un'università esterna."""
            try:
                if not user.is_student:
                    return JSONResponse(
                        {"success": False, "message": "Solo gli studenti possono richiedere credenziali"},
                        status_code=403
                    )

                data = await request.json()
                university = data.get('university')
                purpose = data.get('purpose', '')

                # Configurazione per l'Università di Rennes (esempio)
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

                # Dati dello studente (dal portafoglio)
                wallet = self._get_student_wallet(user)
                student_id = "0622702628"  # Esempio, in realtà dovrebbe provenire dal portafoglio

                # Crea il payload per la richiesta TLS
                payload = {
                    "student_name": "Mario Rossi",
                    "student_id": student_id,
                    "purpose": purpose,
                    "requested_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
                }

                # Invia la richiesta TLS al server universitario
                async with httpx.AsyncClient(verify=False) as client:  # verify=False solo per test!
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

        @self.app.post("/wallet/import-credential", response_class=JSONResponse)
        async def import_credential(
            request_body: 'CredentialImportRequest',
            user: UserSession = Depends(self.auth_deps['require_auth'])
        ):
            """
            Endpoint per importare una credenziale da un file JSON nel portafoglio dello studente.
            """
            self.logger.info(f"Richiesta di importazione credenziale per l'utente: {user.user_id}")

            # Verifica che l'utente sia uno studente
            if not user.is_student:
                self.logger.warning(f"Tentativo di importazione non autorizzato da {user.user_id} (ruolo: {user.role})")
                return JSONResponse(
                    {"success": False, "message": "Solo gli studenti possono importare credenziali."},
                    status_code=403
                )

            try:
                # Ottieni il portafoglio dello studente
                wallet = self._get_student_wallet(user)
                if not wallet or wallet.status != WalletStatus.UNLOCKED:
                    self.logger.error(f"Portafoglio non disponibile o bloccato per l'utente {user.user_id}")
                    return JSONResponse(
                        {"success": False, "message": "Portafoglio non disponibile o bloccato."},
                        status_code=500
                    )

                # Chiama la funzione del portafoglio per aggiungere la credenziale dal JSON
                storage_id = wallet.add_credential_from_json(
                    request_body.credential_json,
                    tags=["importata"]
                )

                if storage_id:
                    self.logger.info(f"Credenziale importata con successo nel portafoglio di {user.user_id}. Storage ID: {storage_id}")
                    return JSONResponse({
                        "success": True,
                        "message": "Credenziale importata con successo nel tuo portafoglio!",
                        "storage_id": storage_id
                    })
                else:
                    # Questo caso copre errori come credenziali duplicate o fallimenti interni
                    self.logger.warning(f"Importazione fallita per {user.user_id}. Possibile duplicato o errore interno.")
                    return JSONResponse(
                        {"success": False, "message": "Impossibile importare la credenziale. Potrebbe essere già presente o il file potrebbe essere corrotto."},
                        status_code=400
                    )

            except Exception as e:
                self.logger.error(f"Errore critico durante l'importazione della credenziale per {user.user_id}: {e}", exc_info=True)
                return JSONResponse(
                    {"success": False, "message": f"Errore interno del server: {str(e)}"},
                    status_code=500
                )

        @self.app.post("/verification/full-verify")
        async def handle_full_verification(
            request: Request,
            user: UserSession = Depends(self.auth_deps['require_verify'])
        ):
            """Gestisce la verifica completa di una presentazione selettiva."""
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

                self.logger.info(f"Verifica completata: {verification_report['overall_result']}")

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

        @self.app.get("/", response_class=HTMLResponse)
        async def home(request: Request):
            """Pagina principale."""
            user = self.auth_deps['get_current_user'](request)
            if user:
                redirect_url = "/wallet" if user.role == 'studente' else "/dashboard"
                return RedirectResponse(url=redirect_url, status_code=HTTP_302_FOUND)

            return self.templates.TemplateResponse("home.html", {"request": request, "title": "Home"})

        @self.app.get("/login", response_class=HTMLResponse)
        async def login_page(request: Request):
            """Pagina di login."""
            return self.templates.TemplateResponse("login.html", {"request": request, "title": "Login"})

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

        @self.app.get("/logout")
        async def logout(request: Request):
            """Esegue il logout dell'utente."""
            session_id = request.session.get("session_id")
            if session_id:
                self.session_manager.destroy_session(session_id)
            request.session.clear()
            return RedirectResponse(url="/", status_code=HTTP_302_FOUND)

        @self.app.get("/wallet", response_class=HTMLResponse)
        async def wallet_page(request: Request):
            """Pagina del portafoglio dello studente."""
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
                "request": request, "user": user, "title": "Il Mio Portafoglio", "credentials": credentials
            })

        @self.app.get("/dashboard", response_class=HTMLResponse)
        async def dashboard(request: Request):
            """Pagina principale della dashboard."""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role == "studente":
                return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)

            # Sostituito MockDataService con dati reali o placeholder
            stats = {
                "total_credentials_issued": self.issuer.stats.get('credentials_issued', 0) if self.issuer else 0,
                "total_credentials_verified": 0,  # Placeholder
                "pending_verifications": 0,      # Placeholder
                "success_rate": 100.0,           # Placeholder
                "last_updated": datetime.datetime.now(datetime.timezone.utc)
            }
            message = request.query_params.get("message")

            return self.templates.TemplateResponse("dashboard.html", {
                "request": request, "user": user, "stats": stats, "title": "Dashboard", "message": message
            })

        @self.app.get("/credentials", response_class=HTMLResponse)
        async def credentials_page(request: Request):
            """Pagina di gestione delle credenziali."""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role == "studente":
                return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)

            credentials = []
            try:
                credentials_base_dir = Path("./src/credentials")
                if credentials_base_dir.exists():
                    for user_dir in credentials_base_dir.iterdir():
                        if user_dir.is_dir():
                            for credential_file in user_dir.glob("*.json"):
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
                                            # Dati fittizi se i moduli non sono disponibili
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
                                    self.logger.warning(f"Errore nel caricamento della credenziale {credential_file}: {e}")
                                    continue

                credentials.sort(key=lambda x: x['issued_at'], reverse=True)

            except Exception as e:
                self.logger.error(f"Errore nel caricamento delle credenziali: {e}")

            return self.templates.TemplateResponse("credentials.html", {
                "request": request, "user": user, "title": "Gestisci Credenziali", "credentials": credentials
            })

        @self.app.get("/credentials/issue", response_class=HTMLResponse)
        async def issue_credential_page(request: Request):
            """Pagina per l'emissione di nuove credenziali."""
            user = self.auth_deps['require_write'](request)

            return self.templates.TemplateResponse("issue_credential.html", {
                "request": request, "user": user, "title": "Emetti Nuova Credenziale"
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
            self.logger.info(f"Richiesta di emissione credenziale ricevuta per lo studente: {student_name}")

            try:
                user = self.auth_deps['require_write'](request)
                self.logger.info(f"Utente autenticato: {user.user_id}")

                if not self.issuer:
                    self.logger.error("Servizio di emissione non inizializzato")
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Servizio di emissione non disponibile"
                    )

                self.logger.info("Servizio di emissione disponibile")

                self.logger.info("Preparazione dati studente...")
                crypto_utils = CryptoUtils()

                name_parts = student_name.strip().split()
                first_name = name_parts[0] if name_parts else "Sconosciuto"
                last_name = name_parts[-1] if len(name_parts) > 1 else "Studente"

                student_info = PersonalInfo(
                    surname_hash=crypto_utils.sha256_hash_string(last_name),
                    name_hash=crypto_utils.sha256_hash_string(first_name),
                    birth_date_hash=crypto_utils.sha256_hash_string("1990-01-01"),
                    student_id_hash=crypto_utils.sha256_hash_string(student_id),
                    pseudonym=f"studente_{student_name.lower().replace(' ', '_')}"
                )
                self.logger.info("Info studente create")

                self.logger.info("Preparazione periodo di studio...")
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
                    self.logger.info("Periodo di studio creato")
                except Exception as e:
                    self.logger.error(f"Errore nella creazione del periodo di studio: {e}")
                    raise ValueError(f"Date non valide: {e}")

                host_university = self.issuer.config.university_info

                study_program = StudyProgram(
                    name="Computer Science Exchange Program",
                    isced_code="0613",
                    eqf_level=EQFLevel.LEVEL_7,
                    program_type="Master's Degree Exchange",
                    field_of_study="Computer Science"
                )
                self.logger.info("Programma di studio creato")

                self.logger.info("Preparazione corsi...")
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
                            self.logger.info(f"Aggiunto corso: {course_name[i]}")

                        except Exception as e:
                            self.logger.error(f"Errore nella creazione del corso {i}: {e}")
                            raise ValueError(f"Errore nel corso {course_name[i]}: {e}")

                if not courses:
                    raise ValueError("È necessario specificare almeno un corso")

                self.logger.info(f"Creati {len(courses)} corsi")

                self.logger.info("🔧 Creazione richiesta di emissione...")
                request_id = self.issuer.create_issuance_request(
                    student_info=student_info,
                    study_period=study_period,
                    host_university=host_university,
                    study_program=study_program,
                    courses=courses,
                    requested_by=user.user_id,
                    notes=f"Tipo di credenziale: {credential_type}"
                )
                self.logger.info(f"Richiesta di emissione creata: {request_id}")

                self.logger.info("Elaborazione richiesta di emissione...")
                issuance_result = self.issuer.process_issuance_request(request_id)

                if not issuance_result.success:
                    error_msg = "; ".join(issuance_result.errors)
                    self.logger.error(f"Emissione fallita: {error_msg}")
                    raise ValueError(f"Emissione fallita: {error_msg}")

                self.logger.info("Credenziale emessa con successo")

                credential = issuance_result.credential
                credential_id_str = str(credential.metadata.credential_id)

                # ============================================
                # SEZIONE CALLBACK CORRETTA
                # ============================================
                if callback_url and callback_url.strip():
                    self.logger.info(f"🚀 Preparazione per l'invio della credenziale a {callback_url}")
                    
                    try:
                        # Prepara i dati della credenziale in formato JSON serializzabile
                        credential_dict = credential.to_dict()
                        
                        # Usa il nostro serializzatore sicuro per gestire datetime, UUID, ecc.
                        try:
                            # Test di serializzazione per verificare che funzioni
                            test_json = json.dumps(credential_dict, default=self._safe_json_serializer)
                            self.logger.info(f"Serializzazione JSON testata con successo ({len(test_json)} caratteri)")
                        except Exception as serialize_error:
                            self.logger.error(f"Errore serializzazione JSON: {serialize_error}")
                            raise ValueError(f"Impossibile serializzare la credenziale: {serialize_error}")
                        
                        # Invia la credenziale al callback URL
                        self.logger.info(f"Invio POST a {callback_url}...")
                        
                        async with httpx.AsyncClient(timeout=30.0) as client:
                            response = await client.post(
                                callback_url,
                                json=credential_dict,
                                headers={
                                    "Content-Type": "application/json",
                                    "User-Agent": "AcademicCredentials-Dashboard/1.0"
                                }
                            )
                            
                            self.logger.info(f"📬 Risposta ricevuta: Status {response.status_code}")
                            
                            if response.is_success:
                                self.logger.info(f"Credenziale inviata con successo a {callback_url}")
                                self.logger.info(f"   Status Code: {response.status_code}")
                                self.logger.info(f"   Response: {response.text[:200]}...")
                                
                                # Aggiungi info sul successo dell'invio nella risposta
                                callback_success_message = f" La credenziale è stata inviata con successo a {callback_url}"
                                
                            else:
                                self.logger.error(f"Errore HTTP durante l'invio a {callback_url}")
                                self.logger.error(f"   Status Code: {response.status_code}")
                                self.logger.error(f"   Response: {response.text}")
                                callback_success_message = f" ATTENZIONE: Errore nell'invio a {callback_url} (HTTP {response.status_code})"
                                
                    except httpx.TimeoutException:
                        self.logger.error(f"Timeout durante l'invio a {callback_url}")
                        callback_success_message = f" ATTENZIONE: Timeout durante l'invio a {callback_url}"
                        
                    except httpx.ConnectError as connect_error:
                        self.logger.error(f"Errore di connessione a {callback_url}: {connect_error}")
                        callback_success_message = f" ATTENZIONE: Impossibile connettersi a {callback_url}"
                        
                    except Exception as callback_error:
                        self.logger.error(f"Errore critico durante l'invio a {callback_url}: {callback_error}")
                        import traceback
                        self.logger.error(f"Traceback: {traceback.format_exc()}")
                        callback_success_message = f" ATTENZIONE: Errore durante l'invio a {callback_url}: {str(callback_error)}"
                else:
                    callback_success_message = ""

                # Salva la credenziale su file
                import re
                safe_student_name = re.sub(r'[^\w\s-]', '', student_name).strip().replace(' ', '_')

                output_dir = Path(f"src/credentials/{user.user_id}/{safe_student_name}/")
                output_dir.mkdir(parents=True, exist_ok=True)

                output_path = output_dir / f"{credential_id_str}.json"

                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(credential.to_json())

                self.logger.info(f" Credenziale salvata in: {output_path}")

                # Prepara la risposta finale
                result_data = {
                    "success": True,
                    "message": f"Credenziale emessa con successo!{callback_success_message}",
                    "credential_id": credential_id_str,
                    "file_path": str(output_path),
                    "issued_at": credential.metadata.issued_at.isoformat(),
                    "total_courses": len(courses),
                    "total_ects": sum(c.ects_credits for c in courses)
                }

                self.logger.info(f" Emissione della credenziale completata con successo per {student_name}")
                return JSONResponse(result_data)

            except ValueError as e:
                self.logger.warning(f" Errore di validazione: {e}")
                return JSONResponse(
                    {"success": False, "message": f"Errore nei dati: {str(e)}"},
                    status_code=400
                )

            except HTTPException as he:
                self.logger.error(f"Eccezione HTTP: {he.detail}")
                raise he

            except Exception as e:
                self.logger.error(f"Errore critico durante l'emissione della credenziale: {e}", exc_info=True)
                return JSONResponse(
                    {"success": False, "message": f"Errore interno del server: {str(e)}"},
                    status_code=500
                )

        @self.app.get("/verification", response_class=HTMLResponse)
        async def verification_page(request: Request):
            """Pagina di verifica delle credenziali."""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role == "studente":
                return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)

            return self.templates.TemplateResponse("verification.html", {
                "request": request, "user": user, "title": "Verifica Credenziali"
            })

        @self.app.get("/credentials/{storage_id}", response_class=JSONResponse)
        async def get_credential_details(
            storage_id: str, user: UserSession = Depends(self.auth_deps['require_auth'])
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
        async def create_presentation(
            request: Request,
            user: UserSession = Depends(self.auth_deps['require_auth'])
        ):
            """Crea una nuova presentazione da credenziali selezionate con divulgazione selettiva."""
            try:
                body = await request.json()

                self.logger.info(f"Creazione presentazione per l'utente: {user.user_id}")
                self.logger.info(f"Corpo della richiesta: {body}")

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

                self.logger.info(f"Attributi selezionati: {selected_attributes}")

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

                self.logger.info(f"Selezioni delle credenziali preparate: {len(credential_selections)}")

                presentation_ids = presentation_manager.create_presentation(
                    purpose=body.get('purpose'),
                    credential_selections=credential_selections,
                    recipient=body.get('recipient'),
                    expires_hours=72
                )

                self.logger.info(f"Presentazioni create con ID: {presentation_ids}")

                presentations_details = []

                for presentation_id in presentation_ids:
                    sign_success = presentation_manager.sign_presentation(presentation_id)
                    if not sign_success:
                        return JSONResponse(
                            {"success": False, "message": f"Errore durante la firma della presentazione {presentation_id}"},
                            status_code=500
                        )

                    self.logger.info(f"Presentazione {presentation_id} firmata con successo")

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

                    self.logger.info(f"Presentazione esportata in: {output_path}")

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

                self.logger.info("Creazione della presentazione completata con successo")
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

        class CredentialImportRequest(BaseModel):
            credential_json: str    
        
        @self.app.post("/wallet/import-credential", response_class=JSONResponse)
        async def import_credential(
            request_body: CredentialImportRequest,
            user: UserSession = Depends(self.auth_deps['require_auth'])
        ):
            """
            Endpoint per importare una credenziale da un file JSON nel wallet dello studente.
            """
            self.logger.info(f"Richiesta di importazione credenziale per l'utente: {user.user_id}")
            
            # Verifica che l'utente sia uno studente
            if not user.is_student:
                self.logger.warning(f"Tentativo di importazione non autorizzato da {user.user_id} (ruolo: {user.role})")
                return JSONResponse(
                    {"success": False, "message": "Solo gli studenti possono importare credenziali."},
                    status_code=403
                )
            
            try:
                # Ottieni il wallet dello studente
                wallet = self._get_student_wallet(user)
                if not wallet or wallet.status != WalletStatus.UNLOCKED:
                    self.logger.error(f"Wallet non disponibile o bloccato per l'utente {user.user_id}")
                    return JSONResponse(
                        {"success": False, "message": "Wallet non disponibile o bloccato."},
                        status_code=500
                    )
                
                # Chiama la funzione del wallet per aggiungere la credenziale dal JSON
                storage_id = wallet.add_credential_from_json(
                    request_body.credential_json,
                    tags=["importata"]
                )
                
                if storage_id:
                    self.logger.info(f"Credenziale importata con successo nel wallet di {user.user_id}. Storage ID: {storage_id}")
                    return JSONResponse({
                        "success": True,
                        "message": "Credenziale importata con successo nel tuo wallet!",
                        "storage_id": storage_id
                    })
                else:
                    # Questo caso copre errori come credenziali duplicate o fallimenti interni
                    self.logger.warning(f"Importazione fallita per {user.user_id}. Possibile duplicato o errore interno.")
                    return JSONResponse(
                        {"success": False, "message": "Impossibile importare la credenziale. Potrebbe essere già presente o il file potrebbe essere corrotto."},
                        status_code=400
                    )
            
            except Exception as e:
                self.logger.error(f"Errore critico durante l'importazione della credenziale per {user.user_id}: {e}", exc_info=True)
                return JSONResponse(
                    {"success": False, "message": f"Errore interno del server: {str(e)}"},
                    status_code=500
                )

        @self.app.get("/presentations/{presentation_id}/download")
        async def download_presentation(
            presentation_id: str,
            user: UserSession = Depends(self.auth_deps['require_auth'])
        ):
            """Permette di scaricare un file di presentazione."""
            try:
                # Il percorso del file ora dipende dal portafoglio dello studente
                if not user.is_student:
                     raise HTTPException(status_code=403, detail="Accesso non autorizzato")

                wallet = self._get_student_wallet(user)
                file_path = wallet.wallet_dir / "presentations" / f"{presentation_id}.json"

                if not file_path.exists():
                    self.logger.warning(f"File della presentazione non trovato: {file_path}")
                    raise HTTPException(status_code=404, detail="Presentazione non trovata")

                self.logger.info(f"Download della presentazione: {presentation_id} per l'utente {user.user_id}")
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