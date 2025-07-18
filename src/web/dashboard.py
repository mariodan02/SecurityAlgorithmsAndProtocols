# =============================================================================
# ACADEMIC CREDENTIALS DASHBOARD - Main Application
# File: web/dashboard.py
# Decentralized Academic Credentials System
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

# FastAPI and web dependencies
from fastapi import FastAPI, Request, HTTPException, Depends, Form, status  # FIXED: Added status import
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

    def _setup_logging(self) -> None:
        """Configures the logging system."""
        logging.basicConfig(
            level=logging.INFO,  # CHANGED: More verbose logging for debugging
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
            # FIXED: Determine absolute paths based on current working directory
            current_dir = Path.cwd()
            self.logger.info(f"Current working directory: {current_dir}")
            
            # Try different possible paths for certificates
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
            
            # Create university info
            university_info = University(
                name="Université de Rennes",
                country="FR",
                city="Rennes",
                erasmus_code="F RENNES01",
                website="https://www.univ-rennes1.fr"
            )
            
            # Create issuer configuration
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
            
    async def _call_secure_api(self, endpoint: str, payload: dict) -> dict:
        """Helper function for calling secure APIs."""
        import httpx
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

        # Deriva common_name e student_id dall'user_id
        # Esempio: "studente_mariorossi" -> "Mario Rossi"
        common_name = user.user_id
        if common_name.startswith("studente_"):
            common_name = common_name[len("studente_"):].replace('_', ' ').title()
        else:
            common_name = common_name.replace('_', ' ').title()
        
        student_id = user.user_id  # Usa l'user_id come student_id per il demo

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
                student_common_name=common_name,
                student_id=student_id
            )

            # Sblocca il wallet per aggiungere la credenziale
            if wallet.unlock_wallet("Unisa2025"):
                 # Aggiunge una credenziale di esempio
                print("Aggiunta di una credenziale di esempio al nuovo wallet...")
                if MODULES_AVAILABLE:
                    try:
                        # Utilizza la factory per creare una credenziale standard
                        sample_credential = CredentialFactory.create_sample_credential()
                        sample_credential.status = CredentialStatus.ACTIVE
                        wallet.add_credential(sample_credential, tags=["esempio", "auto-generata"])
                        print("✅ Credenziale di esempio aggiunta con successo.")
                    except Exception as e:
                        print(f"❌ Errore durante l'aggiunta della credenziale di esempio: {e}")

        # Sblocca il wallet per la sessione corrente se necessario
        if wallet.status == WalletStatus.LOCKED:
            wallet.unlock_wallet("Unisa2025")
            
        return wallet
    
    def _setup_routes(self) -> None:
        """Configures all application routes."""
        
        @self.app.post("/verification/full-verify")
        async def handle_full_verification(request: FullVerificationRequest, user: UserSession = Depends(self.auth_deps['require_verify'])):
            # ... (logica di validazione della presentazione) ...
            
            credential_id = report.credential_id # Ottieni l'ID dal report di validazione
            
            # Verifica lo stato sulla blockchain
            blockchain_status = "Not Checked"
            if self.blockchain_verifier:
                try:
                    result = self.blockchain_verifier.verify_credential(credential_id)
                    blockchain_status = result.get('status', 'ERROR')
                except ValueError as e:
                    blockchain_status = f"ERROR: {e}"

            report.technical_details['blockchain_status'] = blockchain_status
            
            return JSONResponse({"success": True, "verification_report": report.to_dict()})

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
            
            # Format credentials for display
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
                                            # Use mock data if modules are unavailable
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
            FIXED: Handles the issuance of a new credential with better error handling and logging
            """
            self.logger.info(f"📝 Credential issuance request received for student: {student_name}")
            
            try:
                # 1. AUTHENTICATION AND PERMISSION CHECK
                user = self.auth_deps['require_write'](request)
                self.logger.info(f"✅ User authenticated: {user.user_id}")
                
                # 2. CHECK ISSUER SERVICE AVAILABILITY  
                if not self.issuer:
                    self.logger.error("❌ Issuer service not initialized")
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Servizio di emissione non disponibile"
                    )
                
                self.logger.info("✅ Issuer service available")

                # 3. PREPARE STUDENT DATA
                self.logger.info("🔧 Preparing student data...")
                crypto_utils = CryptoUtils()
                
                # Handle student name parsing more safely
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

                # 4. PREPARE STUDY PERIOD
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

                # 5. HOST UNIVERSITY (same as issuer for demo)
                host_university = self.issuer.config.university_info

                # 6. STUDY PROGRAM
                study_program = StudyProgram(
                    name="Computer Science Exchange Program",
                    isced_code="0613",
                    eqf_level=EQFLevel.LEVEL_7,
                    program_type="Master's Degree Exchange",
                    field_of_study="Computer Science"
                )
                self.logger.info("✅ Study program created")

                # 7. PREPARE COURSES
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
                            
                            # Parse exam date more safely
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

                # 8. VERIFY COURSES
                if not courses:
                    raise ValueError("È necessario specificare almeno un corso")
                
                self.logger.info(f"✅ Created {len(courses)} courses")

                # 9. CREATE ISSUANCE REQUEST
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

                # 10. PROCESS REQUEST
                self.logger.info("⚙️ Processing issuance request...")
                issuance_result = self.issuer.process_issuance_request(request_id)
                
                if not issuance_result.success:
                    error_msg = "; ".join(issuance_result.errors)
                    self.logger.error(f"❌ Issuance failed: {error_msg}")
                    raise ValueError(f"Emissione fallita: {error_msg}")

                self.logger.info("✅ Credential issued successfully")

                # 11. SAVE CREDENTIAL
                credential = issuance_result.credential
                credential_id_str = str(credential.metadata.credential_id)
                
                # Create safe filename
                import re
                safe_student_name = re.sub(r'[^\w\s-]', '', student_name).strip().replace(' ', '_')
                
                # Create output directory
                output_dir = Path(f"src/credentials/{user.user_id}/{safe_student_name}/")
                output_dir.mkdir(parents=True, exist_ok=True)
                
                # File path
                output_path = output_dir / f"{credential_id_str}.json"
                
                # Save credential
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(credential.to_json())
                
                self.logger.info(f"💾 Credential saved to: {output_path}")

                # 12. PREPARE RESULT
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
            presentation: PresentationRequest, user: UserSession = Depends(self.auth_deps['require_auth'])
        ):
            """Creates a new presentation from selected credentials."""
            wallet = self._get_student_wallet(user)
            presentation_manager = PresentationManager(wallet)
            
            credential_selections = [
                {'storage_id': storage_id, 'disclosure_level': 'standard'}
                for storage_id in presentation.credentials
            ]
            
            presentation_id = presentation_manager.create_presentation(
                purpose=presentation.purpose,
                credential_selections=credential_selections,
                recipient=presentation.recipient,
                expires_hours=72
            )
            
            presentation_manager.sign_presentation(presentation_id)
            
            export_dir = Path("./presentations")
            export_dir.mkdir(exist_ok=True)
            output_path = export_dir / f"{presentation_id}.json"
            
            presentation_manager.export_presentation(
                presentation_id, 
                str(output_path),
                PresentationFormat(presentation.format)
            )
            
            return {
                "presentation_id": presentation_id,
                "download_url": f"/presentations/{presentation_id}/download"
            }
        
        @self.app.get("/presentations/{presentation_id}/download")
        async def download_presentation(
            presentation_id: str, user: UserSession = Depends(self.auth_deps['require_auth'])
        ):
            """Downloads a presentation file."""
            file_path = Path(f"./presentations/{presentation_id}.json")
            
            if not file_path.exists():
                raise HTTPException(status_code=404, detail="Presentation not found")
            
            return FileResponse(file_path, filename=f"presentation_{presentation_id[:8]}.json")

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