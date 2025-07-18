# =============================================================================
# ACADEMIC CREDENTIALS DASHBOARD - Clean & Professional Version
# File: web/dashboard.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import json
import uuid
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import asyncio
import logging
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any, Union  

# FastAPI e web dependencies
from fastapi import FastAPI, Request, HTTPException, Depends, Form, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_302_FOUND, HTTP_403_FORBIDDEN

# Pydantic per validazione
from pydantic import BaseModel, Field, validator

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
    templates_dir: str = "./src//web/templates"
    static_dir: str = "./src//web/static"
    session_timeout_minutes: int = 60
    max_file_size_mb: int = 10

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)

class UserSession(BaseModel):
    user_id: str
    university_name: str
    role: str
    permissions: List[str]
    login_time: datetime.datetime
    last_activity: datetime.datetime

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
        
        self.sessions[session_id] = UserSession(
            user_id=username,
            university_name=user_info["university"],
            role=user_info["role"],
            permissions=permissions,
            login_time=datetime.datetime.utcnow(),
            last_activity=datetime.datetime.utcnow()
        )
        
        return session_id
    
    def get_session(self, session_id: str) -> Optional[UserSession]:
        """Recupera una sessione esistente"""
        if session_id not in self.sessions:
            return None
            
        session = self.sessions[session_id]
        
        # Controlla se la sessione è scaduta
        if self._is_session_expired(session):
            del self.sessions[session_id]
            return None
        
        # Aggiorna l'ultima attività
        session.last_activity = datetime.datetime.utcnow()
        return session
    
    def destroy_session(self, session_id: str) -> None:
        """Distrugge una sessione"""
        self.sessions.pop(session_id, None)
    
    def _is_session_expired(self, session: UserSession) -> bool:
        """Controlla se una sessione è scaduta"""
        expiry_time = session.last_activity + datetime.timedelta(minutes=self.timeout_minutes)
        return datetime.datetime.utcnow() > expiry_time

class MockDataService:
    """Servizio per dati mock/demo"""
    
    @staticmethod
    def get_dashboard_stats() -> DashboardStats:
        return DashboardStats(
            total_credentials_issued=47,
            total_credentials_verified=32,
            pending_verifications=5,
            success_rate=94.7,
            last_updated=datetime.datetime.utcnow()
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

def check_user_permission(user: UserSession, permission: str) -> bool:
    """Controlla se l'utente ha un permesso specifico"""
    return permission in user.permissions

def require_write_permission(request: Request, session_manager: SessionManager) -> UserSession:
    """Dependency che richiede il permesso di scrittura"""
    user = get_current_user(request, session_manager)
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

def require_verify_permission(request: Request, session_manager: SessionManager) -> UserSession:
    """Dependency che richiede il permesso di verifica"""
    user = get_current_user(request, session_manager)
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

def require_admin_permission(request: Request, session_manager: SessionManager) -> UserSession:
    """Dependency che richiede il permesso di amministrazione"""
    user = get_current_user(request, session_manager)
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

# =============================================================================
# CLASSE PRINCIPALE DASHBOARD
# =============================================================================

class AcademicCredentialsDashboard:
    """
    Dashboard principale per la gestione delle credenziali accademiche.
    
    Fornisce un'interfaccia web per studenti, università e verificatori
    per gestire l'intero ciclo di vita delle credenziali digitali.
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
            level=logging.INFO if not self.config.debug else logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
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
        """Crea le dependency di autenticazione che chiudono su session_manager"""
        
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
        self.logger.info("🚀 INIZIO Inizializzazione componenti di sistema...")
        
        # Import dei moduli del sistema (con gestione errori)
        self.issuer = None
        self.verification_engine = None
        
        try:
            # Import condizionali dei moduli del progetto
            self.logger.info("📦 Step 1: Aggiungendo path...")
            import sys
            sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            self.logger.info("✅ Path aggiunto")
            
            self.logger.info("📦 Step 2: Importando credentials.issuer...")
            from credentials.issuer import AcademicCredentialIssuer, IssuerConfiguration
            self.logger.info("✅ credentials.issuer importato")
            
            self.logger.info("📦 Step 3: Importando credentials.models...")
            from credentials.models import University
            self.logger.info("✅ credentials.models importato")
            
            self.logger.info("📦 Step 4: Creando configurazione...")
            # Configurazione dell'issuer per Université de Rennes
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
                private_key_password="SecurePassword123!",
                backup_enabled=True,
                backup_directory="./src/credentials/backups"
            )
            self.logger.info("✅ Configurazione creata")
            
            # Verifica esistenza file di certificati e chiavi
            self.logger.info("🔍 Step 5: Verificando files...")
            cert_path = Path(issuer_config.certificate_path)
            key_path = Path(issuer_config.private_key_path)
            
            self.logger.info(f"🔍 Controllo certificato: {cert_path}")
            self.logger.info(f"🔍 Exists: {cert_path.exists()}")
            
            self.logger.info(f"🔍 Controllo chiave: {key_path}")
            self.logger.info(f"🔍 Exists: {key_path.exists()}")
            
            if not cert_path.exists():
                self.logger.error(f"❌ ERRORE: Certificato non trovato: {cert_path}")
                self.logger.info("💡 Eseguire: cd src/pki && python certificate_authority.py")
                return
                
            if not key_path.exists():
                self.logger.error(f"❌ ERRORE: Chiave privata non trovata: {key_path}")
                self.logger.info("💡 Eseguire: cd src/pki && python certificate_authority.py")
                return
            
            self.logger.info("✅ File certificato e chiave trovati")
            
            # Inizializza issuer
            self.logger.info("🏗️ Step 6: Inizializzando issuer...")
            self.logger.info("🏗️ Chiamando AcademicCredentialIssuer(config=issuer_config)...")
            
            self.issuer = AcademicCredentialIssuer(config=issuer_config)
            
            self.logger.info("✅ Credential Issuer inizializzato correttamente")
            self.logger.info(f"✅ Issuer type: {type(self.issuer)}")
            
            # Crea directory base per le credenziali
            self.logger.info("📁 Step 7: Creando directory...")
            credentials_dir = Path("./src/credentials")
            credentials_dir.mkdir(parents=True, exist_ok=True)
            
            backups_dir = Path("./src/credentials/backups")
            backups_dir.mkdir(parents=True, exist_ok=True)
            
            self.logger.info("✅ Directory di sistema create")
            self.logger.info("🎉 FINE: Inizializzazione completata con successo!")
            
        except ImportError as e:
            self.logger.error(f"❌ ERRORE import moduli: {e}")
            self.logger.error(f"❌ Traceback completo:")
            import traceback
            traceback.print_exc()
        except Exception as e:
            self.logger.error(f"🔥 ERRORE durante l'inizializzazione: {e}")
            self.logger.error(f"🔥 Traceback completo:")
            import traceback
            traceback.print_exc()

    def _setup_routes(self) -> None:
        """Configura tutte le route dell'applicazione"""

        @self.app.get("/debug/force-init")
        async def force_initialization(request: Request):
            try:
                self.logger.info("🔄 Forzando re-inizializzazione...")
                self._initialize_system_components()
                return {
                    "success": True,
                    "issuer_initialized": self.issuer is not None,
                    "issuer_type": type(self.issuer).__name__ if self.issuer else None
                }
            except Exception as e:
                return {
                    "success": False,
                    "error": str(e)
                }
        
        @self.app.get("/", response_class=HTMLResponse)
        async def home(request: Request):
            """Pagina principale"""
            user = self.auth_deps['get_current_user'](request)
            if user:
                redirect_url = "/wallet" if user.role == 'studente' else "/dashboard"
                return RedirectResponse(url=redirect_url, status_code=HTTP_302_FOUND)
            
            return self.templates.TemplateResponse("base.html", {
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
        
        # === ROUTE PER STUDENTI ===
        
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
        
        @self.app.post("/wallet/create-presentation")
        async def create_presentation(request: Request, presentation_req: PresentationRequest):
            """API per creare una presentazione selettiva"""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role != "studente":
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Accesso negato")
            
            try:
                # Simula la creazione della presentazione
                presentation_id = f"pres_{uuid.uuid4()}"
                download_link = f"/downloads/{presentation_id}.json"
                
                self.logger.info(f"Created presentation {presentation_id} for user {user.user_id}")
                
                return JSONResponse({
                    "success": True,
                    "message": "Presentazione creata con successo!",
                    "presentation_id": presentation_id,
                    "download_link": download_link
                })
                
            except Exception as e:
                self.logger.error(f"Error creating presentation: {e}")
                return JSONResponse({
                    "success": False,
                    "message": "Errore nella creazione della presentazione"
                }, status_code=500)
        
        # === ROUTE PER PERSONALE UNIVERSITARIO ===
        
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
                # Directory base delle credenziali
                credentials_base_dir = Path("./src/credentials")
                
                if credentials_base_dir.exists():
                    # Cerca in tutte le directory utente
                    for user_dir in credentials_base_dir.iterdir():
                        if user_dir.is_dir():
                            # Cerca file di credenziali in questa directory
                            for credential_file in user_dir.glob("credential_*.json"):
                                try:
                                    with open(credential_file, 'r', encoding='utf-8') as f:
                                        from credentials.models import AcademicCredential
                                        credential_data = json.load(f)
                                        credential = AcademicCredential.from_dict(credential_data)
                                        
                                        # Estrae informazioni per la tabella
                                        summary = credential.get_summary()
                                        credentials.append({
                                            'credential_id': summary['credential_id'],
                                            'student_name': summary['subject_pseudonym'],
                                            'issued_at': summary['issued_at'][:19],  # Remove microseconds
                                            'issued_by': credential.issuer.name,
                                            'status': summary['status'].title(),
                                            'total_courses': summary['total_courses'],
                                            'total_ects': summary['total_ects'],
                                            'file_path': str(credential_file)
                                        })
                                except Exception as e:
                                    self.logger.warning(f"Error loading credential {credential_file}: {e}")
                                    continue
                
                # Ordina per data di emissione (più recenti prima)
                credentials.sort(key=lambda x: x['issued_at'], reverse=True)
                
            except ExcFeption as e:
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
            """Gestisce l'emissione reale di una nuova credenziale"""
            
            # 🔍 DEBUG AUTORIZZAZIONE
            try:
                current_user = self.auth_deps['get_current_user'](request)
                self.logger.info(f"🔍 Current user: {current_user}")
                
                if current_user:
                    self.logger.info(f"🔍 User permissions: {current_user.permissions}")
                    self.logger.info(f"🔍 User role: {current_user.role}")
                else:
                    self.logger.error("❌ No current user found")
                    
                user = self.auth_deps['require_write'](request)
                self.logger.info(f"✅ Authorization passed for user: {user.user_id}")
                
            except Exception as e:
                self.logger.error(f"❌ Authorization failed: {e}")
                return JSONResponse({
                    "success": False,
                    "message": f"Errore autorizzazione: {str(e)}"
                }, status_code=403)
            
            # 🔍 DEBUG ISSUER
            self.logger.info(f"🔍 DEBUG: self.issuer = {self.issuer}")
            
            try:
                if not self.issuer:
                    self.logger.error("❌ Issuer not initialized")
                    raise HTTPException(status_code=500, detail="Servizio di emissione non disponibile")
                        
                # Importa modelli necessari
                from credentials.models import (
                    PersonalInfo, Course, StudyPeriod, StudyProgram, University,
                    ExamGrade, GradeSystem, StudyType, EQFLevel
                )
                from crypto.foundations import CryptoUtils
                
                crypto_utils = CryptoUtils()
                
                # Crea directory per l'utente
                user_dir = Path(f"./src/credentials/{user.user_id}")
                user_dir.mkdir(parents=True, exist_ok=True)
                
                # 1. Crea PersonalInfo con hash per privacy
                student_info = PersonalInfo(
                    surname_hash=crypto_utils.sha256_hash_string(student_name.split()[-1]),  # Ultimo nome
                    name_hash=crypto_utils.sha256_hash_string(student_name.split()[0]),      # Primo nome
                    birth_date_hash=crypto_utils.sha256_hash_string("1990-01-01"),         # Data fittizia
                    student_id_hash=crypto_utils.sha256_hash_string(student_id),
                    pseudonym=f"student_{student_name.lower().replace(' ', '_')}"
                )
                
                # 2. Crea StudyPeriod
                study_period = StudyPeriod(
                    start_date=datetime.datetime.fromisoformat(study_period_start + "T00:00:00+00:00"),
                    end_date=datetime.datetime.fromisoformat(study_period_end + "T23:59:59+00:00"),
                    study_type=StudyType.ERASMUS,
                    academic_year=f"{datetime.datetime.fromisoformat(study_period_start).year}/{datetime.datetime.fromisoformat(study_period_start).year + 1}",
                    semester="Fall/Spring"
                )
                
                # 3. Università ospitante (dove lo studente ha studiato)
                host_university = University(
                    name="Université de Rennes",
                    country="FR",
                    erasmus_code="F RENNES01",
                    city="Rennes",
                    website="https://www.univ-rennes1.fr"
                )
                
                # 4. Programma di studio
                study_program = StudyProgram(
                    name="Computer Science and Engineering",
                    isced_code="0613",
                    eqf_level=EQFLevel.LEVEL_7,
                    program_type="Master's Degree",
                    field_of_study="Computer Science"
                )
                
                # 5. Crea lista corsi
                courses = []
                for i in range(len(course_name)):
                    if course_name[i] and course_cfu[i] and course_grade[i]:
                        # Parsea il voto
                        grade_score = course_grade[i]
                        passed = not grade_score.lower() in ['f', 'fail', 'insufficiente']
                        
                        # Determina sistema di voti
                        if '/' in grade_score:
                            grade_system = GradeSystem.ITALIAN_30
                            ects_grade = "B"  # Default
                        else:
                            grade_system = GradeSystem.ECTS_GRADE
                            ects_grade = grade_score.upper()
                        
                        exam_grade = ExamGrade(
                            score=grade_score,
                            passed=passed,
                            grade_system=grade_system,
                            ects_grade=ects_grade
                        )
                        
                        # Data esame
                        exam_date = datetime.datetime.fromisoformat(course_date[i] + "T10:00:00+00:00") if course_date[i] else study_period.end_date
                        
                        course = Course(
                            course_name=course_name[i],
                            course_code=f"RENNES-{i+1:03d}",
                            isced_code="0613",
                            grade=exam_grade,
                            exam_date=exam_date,
                            ects_credits=int(course_cfu[i]),
                            professor=f"Prof. {chr(65+i%26)}. Dupont",
                            course_description=f"Corso di {course_name[i]}",
                            prerequisites=[],
                            learning_outcomes=[]
                        )
                        courses.append(course)
                
                if not courses:
                    raise ValueError("Almeno un corso deve essere specificato")
                
                # 6. Crea richiesta di emissione
                self.logger.info(f"Creating issuance request for {student_info.pseudonym}")
                
                request_id = self.issuer.create_issuance_request(
                    student_info=student_info,
                    study_period=study_period,
                    host_university=host_university,
                    study_program=study_program,
                    courses=courses,
                    requested_by=user.user_id,
                    notes=f"Credenziale di tipo: {credential_type}"
                )
                
                # 7. Processa la richiesta per emettere la credenziale
                self.logger.info(f"Processing issuance request {request_id}")
                issuance_result = self.issuer.process_issuance_request(request_id)
                
                if not issuance_result.success:
                    error_msg = "; ".join(issuance_result.errors)
                    raise ValueError(f"Errore emissione credenziale: {error_msg}")
                
                # 8. Salva la credenziale nella directory utente
                credential = issuance_result.credential
                credential_filename = f"credential_{issuance_result.credential_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                credential_path = user_dir / credential_filename
                
                with open(credential_path, 'w', encoding='utf-8') as f:
                    f.write(credential.to_json())
                
                # 9. Salva anche un summary leggibile
                summary_path = user_dir / f"summary_{issuance_result.credential_id}.txt"
                with open(summary_path, 'w', encoding='utf-8') as f:
                    summary = credential.get_summary()
                    f.write("=== CREDENZIALE ACCADEMICA ===\n")
                    f.write(f"ID: {summary['credential_id']}\n")
                    f.write(f"Emessa da: {summary['issuer']}\n")
                    f.write(f"Per: {summary['subject_pseudonym']}\n")
                    f.write(f"Università ospitante: {summary['host_university']}\n")
                    f.write(f"Programma: {summary['program']}\n")
                    f.write(f"Periodo: {summary['study_period']}\n")
                    f.write(f"Corsi: {summary['total_courses']}\n")
                    f.write(f"ECTS: {summary['total_ects']}\n")
                    f.write(f"Media: {summary['average_grade']}\n")
                    f.write(f"Stato: {summary['status']}\n")
                    f.write(f"Firmata: {'Sì' if summary['signed'] else 'No'}\n")
                    f.write(f"Emessa il: {summary['issued_at']}\n")
                
                self.logger.info(f"Credential successfully issued and saved: {credential_path}")
                self.logger.info(f"User {user.user_id} issued credential {issuance_result.credential_id} for {student_info.pseudonym}")
                
                # Return success con dettagli
                return JSONResponse({
                    "success": True,
                    "message": "Credenziale emessa con successo!",
                    "credential_id": issuance_result.credential_id,
                    "file_path": str(credential_path),
                    "issued_at": issuance_result.issued_at.isoformat() if issuance_result.issued_at else None,
                    "total_courses": len(courses),
                    "total_ects": sum(c.ects_credits for c in courses)
                })
                
            except ValueError as e:
                self.logger.error(f"Validation error: {e}")
                return JSONResponse({
                    "success": False,
                    "message": f"Errore di validazione: {str(e)}"
                }, status_code=400)
                
            except Exception as e:
                self.logger.error(f"Error issuing credential: {e}")
                import traceback
                traceback.print_exc()
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
        
        @self.app.post("/verification/verify")
        async def verify_presentation(request: Request, verification_req: VerificationRequest):
            """API per verificare una presentazione"""
            user = self.auth_deps['require_verify'](request)
            
            try:
                # Simula la verifica
                verification_result = {
                    "verification_id": f"verify_{uuid.uuid4()}",
                    "result": "valid",
                    "verified_at": datetime.datetime.utcnow().isoformat(),
                    "verified_by": user.user_id,
                    "confidence_score": 0.97,
                    "details": {
                        "credentials_verified": 2,
                        "attributes_checked": 8,
                        "security_checks_passed": 5
                    }
                }
                
                return JSONResponse({
                    "success": True,
                    "verification_result": verification_result
                })
                
            except Exception as e:
                self.logger.error(f"Error verifying presentation: {e}")
                return JSONResponse({
                    "success": False,
                    "message": "Errore durante la verifica"
                }, status_code=500)
        
        @self.app.get("/api/verification/pending")
        async def get_pending_verifications(request: Request):
            """API per ottenere le verifiche in sospeso"""
            user = self.auth_deps['get_current_user'](request)
            if not user:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN)
            
            pending = self.mock_data.get_pending_verifications()
            return JSONResponse({"pending": pending})
        
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
        
        @self.app.get("/testing", response_class=HTMLResponse)
        async def testing_page(request: Request):
            """Pagina esecuzione test (solo admin)"""
            user = self.auth_deps['require_admin'](request)
            
            test_results = self.mock_data.get_test_results()
            
            return self.templates.TemplateResponse("testing.html", {
                "request": request,
                "user": user,
                "title": "Test Sistema",
                "test_results": test_results
            })
        
        @self.app.post("/testing/run")
        async def run_tests(request: Request):
            """API per eseguire i test del sistema"""
            user = self.auth_deps['require_admin'](request)
            
            try:
                # Simula l'esecuzione dei test
                test_result = {
                    "test_run_id": f"test_{uuid.uuid4()}",
                    "duration_sec": 12.5,
                    "total_tests": 20,
                    "passed_tests": 18,
                    "failed_tests": 2
                }
                
                self.logger.info(f"Test suite executed by {user.user_id}")
                
                return JSONResponse({
                    "success": True,
                    "test_result": test_result
                })
                
            except Exception as e:
                self.logger.error(f"Error running tests: {e}")
                return JSONResponse({
                    "success": False,
                    "message": "Errore durante l'esecuzione dei test"
                }, status_code=500)
        
        # === ROUTE DI UTILITÀ ===
        
        @self.app.get("/health")
        async def health_check():
            """Health check endpoint"""
            return JSONResponse({
                "status": "healthy",
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "version": "2.0.0"
            })
    
    def run(self, host: Optional[str] = None, port: Optional[int] = None):
        """Avvia il server"""
        import uvicorn
        
        host = host or self.config.host
        port = port or self.config.port
        
        self.logger.info(f"🚀 Avvio Academic Credentials Dashboard")
        self.logger.info(f"📍 URL: http://{host}:{port}")
        self.logger.info(f"🔧 Debug mode: {self.config.debug}")
        
        uvicorn.run(
            self.app,
            host=host,
            port=port,
            log_level="info" if not self.config.debug else "debug"
        )

# =============================================================================
# PUNTO DI INGRESSO
# =============================================================================

# Istanza globale per uvicorn
_dashboard_instance = None

def get_dashboard_app() -> FastAPI:
    """Factory function per ottenere l'istanza dell'app"""
    global _dashboard_instance
    if _dashboard_instance is None:
        _dashboard_instance = AcademicCredentialsDashboard()
    return _dashboard_instance.app

# App instance per uvicorn
app = get_dashboard_app()

if __name__ == "__main__":
    print("🌐 Avvio Academic Credentials Dashboard in modalità standalone...")
    dashboard = AcademicCredentialsDashboard()
    dashboard.run()