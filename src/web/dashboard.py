# =============================================================================
# ACADEMIC CREDENTIALS DASHBOARD - Clean & Professional Version
# File: web/dashboard.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import base64
import os
import json
import uuid
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
from dataclasses import dataclass

# FastAPI e web dependencies
from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_302_FOUND, HTTP_403_FORBIDDEN

# Pydantic per validazione
from pydantic import BaseModel, Field

# Import condizionali per evitare errori se i moduli non sono disponibili
try:
    from communication.secure_server import CredentialVerificationRequest
    from credentials.models import AcademicCredential
    from crypto.foundations import CryptoUtils, DigitalSignature
    from credentials.validator import AcademicCredentialValidator, ValidationLevel, ValidationResult, ValidatorConfiguration
    from pki.certificate_manager import CertificateManager
    MODULES_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Alcuni moduli non disponibili: {e}")
    MODULES_AVAILABLE = False

# =============================================================================
# CONFIGURAZIONE E MODELLI DATI
# =============================================================================

@dataclass
class AppConfig:
    """Configurazione centralizzata dell'applicazione"""
    secret_key: str = "Unisa2025"
    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = True
    templates_dir: str = "./src/web/templates"
    static_dir: str = "./src/web/static"
    session_timeout_minutes: int = 60
    max_file_size_mb: int = 10
    secure_server_url: str = "https://localhost:8443"
    secure_server_api_key: str = "unisa_key_123"

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
    credentials: List[Dict[str, str]]

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
    """Servizio per la gestione dell'autenticazione"""
    
    VALID_USERS = {
        "studente_mariorossi": {"role": "studente", "university": "Università di Salerno"},
        "issuer_rennes": {"role": "issuer", "university": "Université de Rennes"},
        "verifier_unisa": {"role": "verifier", "university": "Università di Salerno"},
        "admin_system": {"role": "admin", "university": "Sistema Centrale"}
    }
    
    @classmethod
    def authenticate_user(cls, username: str, password: str) -> Optional[Dict[str, str]]:
        """Autentica un utente con username e password"""
        if username in cls.VALID_USERS and password == "Unisa2025":
            return cls.VALID_USERS[username]
        return None
    
    @classmethod
    def get_user_permissions(cls, role: str) -> List[str]:
        """Restituisce i permessi dell'utente basati sul ruolo"""
        permissions_map = {
            "studente": ["read", "share"],
            "issuer": ["read", "write", "issue"],
            "verifier": ["read", "verify"],
            "admin": ["read", "write", "verify", "admin"]
        }
        return permissions_map.get(role, ["read"])

class SessionManager:
    """Gestore delle sessioni utente"""
    
    def __init__(self, timeout_minutes: int = 60):
        self.sessions: Dict[str, UserSession] = {}
        self.timeout_minutes = timeout_minutes
    
    def create_session(self, user_info: Dict[str, str], username: str) -> str:
        """Crea una nuova sessione utente"""
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
        """Recupera una sessione esistente"""
        if session_id not in self.sessions:
            return None
            
        session = self.sessions[session_id]
        
        if self._is_session_expired(session):
            del self.sessions[session_id]
            return None
        
        session.last_activity = datetime.datetime.now(datetime.timezone.utc)
        return session
    
    def destroy_session(self, session_id: str) -> None:
        """Distrugge una sessione"""
        self.sessions.pop(session_id, None)
    
    def _is_session_expired(self, session: UserSession) -> bool:
        """Controlla se una sessione è scaduta"""
        expiry_time = session.last_activity + datetime.timedelta(minutes=self.timeout_minutes)
        return datetime.datetime.now(datetime.timezone.utc) > expiry_time

class MockDataService:
    """Servizio per dati mock/demo"""
    
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
                "status": "Attiva"
            },
            {
                "credential_id": "cred_germany_456", 
                "issuer": "TU München",
                "issue_date": "2024-02-20",
                "total_courses": 4,
                "status": "Attiva"
            }
        ]
    
    @staticmethod
    def get_pending_verifications() -> List[Dict[str, str]]:
        return [
            {"student_name": "Mario Rossi", "purpose": "Riconoscimento CFU", "status": "In elaborazione"},
            {"student_name": "Anna Bianchi", "purpose": "Iscrizione Master", "status": "Documentazione richiesta"},
            {"student_name": "Luca Verdi", "purpose": "Erasmus+", "status": "In elaborazione"}
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
            "blockchain_status": "Operativo",
            "database_status": "Operativo"
        }
    
    @staticmethod
    def get_test_results() -> Dict[str, Any]:
        return {
            "last_run": "2025-01-15 14:30:00",
            "passed": 18,
            "failed": 2,
            "success_rate": "90%"
        }

# =============================================================================
# MIDDLEWARE E DIPENDENZE
# =============================================================================

def get_current_user(request: Request, session_manager: SessionManager) -> Optional[UserSession]:
    """Dependency per ottenere l'utente corrente dalla sessione"""
    session_id = request.session.get("session_id")
    if session_id:
        return session_manager.get_session(session_id)
    return None

def require_auth(request: Request, session_manager: SessionManager) -> UserSession:
    """Dependency che richiede autenticazione"""
    user = get_current_user(request, session_manager)
    if not user:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Autenticazione richiesta"
        )
    return user

# =============================================================================
# CLASSE PRINCIPALE DASHBOARD
# =============================================================================

class AcademicCredentialsDashboard:
    """
    Dashboard principale per la gestione delle credenziali accademiche.
    """
    
    def __init__(self, config: Optional[AppConfig] = None):
        self.config = config or AppConfig()
        self.app = FastAPI(
            title="Academic Credentials Dashboard",
            description="Sistema per la gestione decentralizzata delle credenziali accademiche",
            version="2.0.0"
        )
        
        # Servizi
        self.session_manager = SessionManager(self.config.session_timeout_minutes)
        self.mock_data = MockDataService()
        
        # Setup logging
        self._setup_logging()
        
        # Inizializzazione componenti
        self._setup_directories()
        self._setup_templates()
        self._setup_middleware()
        self._setup_static_files()
        
        # Crea le dependency di autenticazione
        self.auth_deps = self._create_auth_dependencies()
        
        self._setup_routes()
        self._initialize_system_components()
    
    def _setup_logging(self) -> None:
        """Configura il sistema di logging"""
        logging.basicConfig(
            level=logging.WARNING,
            format='%(levelname)s - %(message)s',
            force=True
        )
        self.logger = logging.getLogger(__name__)
        
        logging.getLogger('uvicorn').setLevel(logging.WARNING)
        logging.getLogger('fastapi').setLevel(logging.WARNING)
        logging.getLogger('uvicorn.access').setLevel(logging.ERROR)

    def run(self, host: Optional[str] = None, port: Optional[int] = None):
        """Avvia il server"""
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

    def _setup_directories(self) -> None:
        """Crea le directory necessarie"""
        self.templates_dir = Path(self.config.templates_dir)
        self.static_dir = Path(self.config.static_dir)
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.static_dir.mkdir(parents=True, exist_ok=True)
    
    def _setup_templates(self) -> None:
        """Configura il sistema di template"""
        self.templates = Jinja2Templates(directory=str(self.templates_dir))
    
    def _setup_middleware(self) -> None:
        """Configura i middleware"""
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
        """Configura i file statici"""
        self.app.mount("/static", StaticFiles(directory=str(self.static_dir)), name="static")
    
    def _create_auth_dependencies(self):
        """Crea le dependency di autenticazione"""
        
        def get_current_user_dep(request: Request) -> Optional[UserSession]:
            return get_current_user(request, self.session_manager)
        
        def require_auth_dep(request: Request) -> UserSession:
            user = get_current_user(request, self.session_manager)
            if not user:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="Autenticazione richiesta"
                )
            return user
        
        def require_write_permission_dep(request: Request) -> UserSession:
            user = get_current_user(request, self.session_manager)
            if not user:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="Autenticazione richiesta"
                )
            
            if "write" not in user.permissions:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="Permesso di scrittura richiesto"
                )
            return user
        
        def require_verify_permission_dep(request: Request) -> UserSession:
            user = get_current_user(request, self.session_manager)
            if not user:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="Autenticazione richiesta"
                )
            
            if "verify" not in user.permissions:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="Permesso di verifica richiesto"
                )
            return user
        
        def require_admin_permission_dep(request: Request) -> UserSession:
            user = get_current_user(request, self.session_manager)
            if not user:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="Autenticazione richiesta"
                )
            
            if "admin" not in user.permissions:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="Permesso di amministrazione richiesto"
                )
            return user
        
        return {
            'get_current_user': get_current_user_dep,
            'require_auth': require_auth_dep,
            'require_write': require_write_permission_dep,
            'require_verify': require_verify_permission_dep,
            'require_admin': require_admin_permission_dep
        }

    def _initialize_system_components(self) -> None:
        """Inizializza i componenti del sistema"""
        self.issuer = None
        self.verification_engine = None
        
        if not MODULES_AVAILABLE:
            self.logger.warning("⚠️ Moduli del sistema non disponibili - modalità demo")
            return
        
        try:
            import sys
            sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            
            from credentials.issuer import AcademicCredentialIssuer, IssuerConfiguration
            from credentials.models import University
            
            issuer_config = IssuerConfiguration(
                university_info=University(
                    name="Université de Rennes",
                    country="FR",
                    city="Rennes",
                    erasmus_code="F RENNES01",
                    website="https://www.univ-rennes1.fr"
                ),
                certificate_path="./certificates/issued/university_F_RENNES01_1001.pem",
                private_key_path="./keys/universite_rennes_private.pem",
                private_key_password="Unisa2025",
                backup_enabled=True,
                backup_directory="./src/credentials/backups"
            )
            
            cert_path = Path(issuer_config.certificate_path)
            key_path = Path(issuer_config.private_key_path)
            
            if not cert_path.exists():
                self.logger.error(f"❌ Certificato non trovato: {cert_path}")
                return
                    
            if not key_path.exists():
                self.logger.error(f"❌ Chiave privata non trovata: {key_path}")
                return
            
            original_logging_level = self.logger.level
            self.logger.setLevel(logging.CRITICAL)
            
            self.issuer = AcademicCredentialIssuer(config=issuer_config)
            
            self.logger.setLevel(original_logging_level)
            
            credentials_dir = Path("./src/credentials")
            credentials_dir.mkdir(parents=True, exist_ok=True)
            
            backups_dir = Path("./src/credentials/backups")
            backups_dir.mkdir(parents=True, exist_ok=True)
            
            if self.issuer:
                self.logger.info("✅ Sistema componenti inizializzato correttamente")
                
        except ImportError as e:
            self.logger.error(f"❌ ERRORE import moduli: {e}")
        except Exception as e:
            self.logger.error(f"🔥 ERRORE durante l'inizializzazione: {e}")

    async def _call_secure_api(self, endpoint: str, payload: dict) -> dict:
        """Helper per chiamare le API sicure"""
        import httpx
        url = f"{self.config.secure_server_url}{endpoint}"
        headers = {"Authorization": f"Bearer {self.config.secure_server_api_key}"}
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()

    def _setup_routes(self) -> None:
        """Configura tutte le route dell'applicazione"""
        
        @self.app.get("/", response_class=HTMLResponse)
        async def home(request: Request):
            """Pagina principale"""
            user = self.auth_deps['get_current_user'](request)
            if user:
                redirect_url = "/wallet" if user.role == 'studente' else "/dashboard"
                return RedirectResponse(url=redirect_url, status_code=HTTP_302_FOUND)
            
            return self.templates.TemplateResponse("home.html", {
                "request": request,
                "title": "Home"
            })
        
        @self.app.get("/login", response_class=HTMLResponse)
        async def login_page(request: Request):
            """Pagina di login"""
            return self.templates.TemplateResponse("login.html", {
                "request": request,
                "title": "Login"
            })
        
        @self.app.post("/login")
        async def login(request: Request, username: str = Form(...), password: str = Form(...)):
            """Gestisce il login dell'utente"""
            try:
                user_info = AuthenticationService.authenticate_user(username, password)
                if user_info:
                    session_id = self.session_manager.create_session(user_info, username)
                    request.session["session_id"] = session_id
                    
                    redirect_url = "/wallet" if user_info["role"] == "studente" else "/dashboard"
                    self.logger.info(f"Login successful for {username} (role: {user_info['role']})")
                    
                    return RedirectResponse(url=redirect_url, status_code=HTTP_302_FOUND)
                
                return self.templates.TemplateResponse("login.html", {
                    "request": request,
                    "error": "Credenziali non valide",
                    "title": "Login"
                })
                
            except Exception as e:
                self.logger.error(f"Login error: {e}")
                return self.templates.TemplateResponse("login.html", {
                    "request": request,
                    "error": "Errore del sistema. Riprova più tardi.",
                    "title": "Login"
                })
        
        @self.app.get("/logout")
        async def logout(request: Request):
            """Logout dell'utente"""
            session_id = request.session.get("session_id")
            if session_id:
                self.session_manager.destroy_session(session_id)
            request.session.clear()
            return RedirectResponse(url="/", status_code=HTTP_302_FOUND)
        
        @self.app.get("/wallet", response_class=HTMLResponse)
        async def wallet_page(request: Request):
            """Wallet dello studente"""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role != "studente":
                return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
            
            credentials = self.mock_data.get_wallet_credentials()
            
            return self.templates.TemplateResponse("student_wallet.html", {
                "request": request,
                "user": user,
                "title": "My Wallet",
                "credentials": credentials
            })
        
        @self.app.get("/dashboard", response_class=HTMLResponse)
        async def dashboard(request: Request):
            """Dashboard principale"""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role == "studente":
                return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
            
            stats = self.mock_data.get_dashboard_stats()
            message = request.query_params.get("message")
            
            return self.templates.TemplateResponse("dashboard.html", {
                "request": request,
                "user": user,
                "stats": stats,
                "title": "Dashboard",
                "message": message
            })
        
        @self.app.get("/credentials", response_class=HTMLResponse)
        async def credentials_page(request: Request):
            """Pagina gestione credenziali"""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role == "studente":
                return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
            
            # Carica credenziali reali dal filesystem
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
                                            # Mock data se i moduli non sono disponibili
                                            credentials.append({
                                                'credential_id': f"mock_{credential_file.stem}",
                                                'student_name': "Mario Rossi",
                                                'issued_at': "2024-01-15 10:30:00",
                                                'issued_by': "Université de Rennes",
                                                'status': "Attiva",
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
                "request": request,
                "user": user,
                "title": "Gestione Credenziali",
                "credentials": credentials
            })
        
        @self.app.get("/credentials/issue", response_class=HTMLResponse)
        async def issue_credential_page(request: Request):
            """Pagina per emettere nuove credenziali"""
            user = self.auth_deps['require_write'](request)
            
            return self.templates.TemplateResponse("issue_credential.html", {
                "request": request,
                "user": user,
                "title": "Emetti Nuova Credenziale"
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
            """Gestisce l'emissione di una nuova credenziale"""
            
            try:
                user = self.auth_deps['require_write'](request)
                
                if not MODULES_AVAILABLE or not self.issuer:
                    return JSONResponse({
                        "success": False,
                        "message": "Servizio di emissione non disponibile - modalità demo"
                    }, status_code=503)
                
                # Il resto dell'implementazione rimane uguale ma con gestione errori migliorata
                return JSONResponse({
                    "success": True,
                    "message": "Credenziale emessa con successo! (Demo mode)",
                    "credential_id": f"demo_{uuid.uuid4()}",
                    "file_path": f"./demo/credential_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    "issued_at": datetime.datetime.now().isoformat(),
                    "total_courses": len([x for x in course_name if x]),
                    "total_ects": sum(int(x) for x in course_cfu if x.isdigit())
                })
                
            except Exception as e:
                self.logger.error(f"Error issuing credential: {e}")
                return JSONResponse({
                    "success": False,
                    "message": f"Errore interno del server: {str(e)}"
                }, status_code=500)
        
        @self.app.get("/verification", response_class=HTMLResponse)
        async def verification_page(request: Request):
            """Pagina di verifica credenziali"""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role == "studente":
                return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
            
            return self.templates.TemplateResponse("verification.html", {
                "request": request,
                "user": user,
                "title": "Verifica Credenziali"
            })
        
        @self.app.get("/integration", response_class=HTMLResponse)
        async def integration_page(request: Request):
            """Pagina integrazione sistemi"""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role == "studente":
                return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
            
            integration_stats = self.mock_data.get_integration_stats()
            
            return self.templates.TemplateResponse("integration.html", {
                "request": request,
                "user": user,
                "title": "Integrazione Sistemi",
                "integration_stats": integration_stats
            })
        
        @self.app.get("/monitoring", response_class=HTMLResponse)
        async def monitoring_page(request: Request):
            """Pagina monitoraggio sistema"""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role == "studente":
                return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
            
            system_health = self.mock_data.get_system_health()
            
            return self.templates.TemplateResponse("monitoring.html", {
                "request": request,
                "user": user,
                "title": "Monitoring Sistema",
                "system_health": system_health
            })
        
        @self.app.get("/health")
        async def health_check():
            """Health check endpoint"""
            return JSONResponse({
                "status": "healthy",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "version": "2.0.0"
            })

# =============================================================================
# PUNTO DI INGRESSO
# =============================================================================

_dashboard_instance = None

def get_dashboard_app() -> FastAPI:
    """Factory function per ottenere l'istanza dell'app"""
    global _dashboard_instance
    if _dashboard_instance is None:
        _dashboard_instance = AcademicCredentialsDashboard()
    return _dashboard_instance.app

app = get_dashboard_app()

if __name__ == "__main__":
    print("🌐 Avvio Academic Credentials Dashboard in modalità standalone...")
    dashboard = AcademicCredentialsDashboard()
    dashboard.run()