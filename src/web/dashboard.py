import os
import sys
import json
import uuid
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

# --- Blocco di Importazione Robusto ---
try:
    src_path = Path(__file__).resolve().parent.parent
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))
    
    from credentials.models import (
        AcademicCredential, CredentialFactory, PersonalInfo, StudyPeriod,
        University, StudyProgram, Course, ExamGrade, GradeSystem, StudyType, EQFLevel
    )
    from credentials.issuer import AcademicCredentialIssuer, IssuerConfiguration
    from pki.certificate_manager import CertificateManager
    from crypto.foundations import CryptoUtils
    MODULES_LOADED = True
    print("✅ Moduli principali del progetto caricati con successo.")
except ImportError as e:
    print(f"❌ ERRORE CRITICO: Import dei moduli principali fallito: {e}")
    MODULES_LOADED = False
# --- Fine del Blocco di Importazione ---

# Dipendenze Web
from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import uvicorn
from pydantic import BaseModel

# Modelli Pydantic
class UserSession(BaseModel):
    user_id: str; university_name: str; role: str; permissions: List[str]; login_time: datetime.datetime; last_activity: datetime.datetime

class DashboardStats(BaseModel):
    total_credentials_issued: int; total_credentials_verified: int; pending_verifications: int; active_students: int; total_credits_processed: int; success_rate: float; last_updated: datetime.datetime

class AcademicCredentialsDashboard:
    """Dashboard web per la gestione delle credenziali accademiche."""

    def __init__(self):
        self.app = FastAPI(title="Academic Credentials Dashboard", version="1.0.0")
        self.secret_key = os.urandom(24).hex()
        base_path = Path(__file__).resolve().parent
        self.templates_dir = base_path / "templates"
        self.static_dir = base_path / "static"
        self.templates = Jinja2Templates(directory=str(self.templates_dir))
        self.sessions: Dict[str, UserSession] = {}
        self.issuer: Optional[AcademicCredentialIssuer] = None
        if MODULES_LOADED: self._initialize_system_components()
        self.mock_data = self._initialize_mock_data()
        self._setup_middleware()
        self._setup_routes()
        print("🌐 Academic Credentials Dashboard inizializzato.")

    def _initialize_system_components(self):
        try:
            self.crypto_utils = CryptoUtils()
            issuer_config = IssuerConfiguration(
                university_info=University(name="Università degli Studi di Salerno", country="IT", city="Fisciano", erasmus_code="I SALERNO01"),
                certificate_path="./certificates/issued/university_I_SALERNO01_1001.pem",
                private_key_path="./keys/universite_rennes_private.pem",
                private_key_password="SecurePassword123!", auto_sign=True, backup_enabled=False
            )
            self.issuer = AcademicCredentialIssuer(issuer_config)
            print("✅ Issuer Reale inizializzato correttamente.")
        except Exception as e:
            print(f"❌ ERRORE: Impossibile inizializzare l'Issuer: {e}")
            self.issuer = None
            
    def _setup_middleware(self):
        self.app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
        self.app.add_middleware(SessionMiddleware, secret_key=self.secret_key)
    
    def _setup_routes(self):
        routes = {
            "/": self.render_home, "/login": self.render_login_page, "/logout": self.handle_logout,
            "/dashboard": self.render_dashboard, "/credentials": self.render_credentials_page,
            "/credentials/issue": self.render_issue_credential_page, "/verification": self.render_verification_page,
            "/integration": self.render_integration_page, "/monitoring": self.render_monitoring_page,
            "/testing": self.render_testing_page,
        }
        for path, endpoint in routes.items(): self.app.get(path, response_class=HTMLResponse)(endpoint)
        self.app.post("/login")(self.handle_login)
        self.app.post("/credentials/issue")(self.handle_issue_credential)
        self.app.mount("/static", StaticFiles(directory=str(self.static_dir)), name="static")

    def get_current_user(self, request: Request) -> Optional[UserSession]:
        session_id = request.session.get("session_id")
        user = self.sessions.get(session_id)
        if user: user.last_activity = datetime.datetime.now(datetime.timezone.utc)
        return user

    async def handle_login(self, request: Request, username: str = Form(...), password: str = Form(...)):
        if username in ["admin", "issuer", "verifier"] and password == "demo123":
            utc_now = datetime.datetime.now(datetime.timezone.utc)
            session_id = f"session_{uuid.uuid4()}"
            permissions = {"admin": ["read", "write", "admin"], "issuer": ["read", "write"], "verifier": ["read"]}.get(username, [])
            self.sessions[session_id] = UserSession(
                user_id=username, university_name="Demo University", role=username, permissions=permissions,
                login_time=utc_now, last_activity=utc_now
            )
            request.session["session_id"] = session_id
            return RedirectResponse(url="/dashboard", status_code=302)
        return self.templates.TemplateResponse("login.html", {"request": request, "title": "Login", "error": "Credenziali non valide"})

    async def handle_logout(self, request: Request):
        session_id = request.session.pop("session_id", None)
        if session_id in self.sessions: del self.sessions[session_id]
        return RedirectResponse(url="/", status_code=302)

    async def render_home(self, request: Request):
        if self.get_current_user(request): return RedirectResponse(url="/dashboard")
        return self.templates.TemplateResponse("home.html", {"request": request, "title": "Home"})

    async def render_login_page(self, request: Request):
        return self.templates.TemplateResponse("login.html", {"request": request, "title": "Login"})
    
    async def render_dashboard(self, request: Request):
        user = self.get_current_user(request)
        if not user: return RedirectResponse(url="/login")
        return self.templates.TemplateResponse("dashboard.html", {"request": request, "user": user, "stats": self._get_dashboard_stats(), "title": "Dashboard"})

    async def render_credentials_page(self, request: Request):
        user = self.get_current_user(request)
        if not user: return RedirectResponse(url="/login")
        credentials = self.issuer.list_credentials() if self.issuer else []
        return self.templates.TemplateResponse("credentials.html", {"request": request, "user": user, "credentials": credentials, "title": "Gestione Credenziali"})

    async def render_issue_credential_page(self, request: Request):
        user = self.get_current_user(request)
        if not user or "write" not in user.permissions: raise HTTPException(403)
        return self.templates.TemplateResponse("issue_credential.html", {"request": request, "user": user, "title": "Emissione Credenziale"})

    async def handle_issue_credential(self, request: Request):
        user = self.get_current_user(request)
        if not user or "write" not in user.permissions: raise HTTPException(403, "Non autorizzato")
        if not self.issuer: return JSONResponse({"success": False, "message": "Servizio di emissione non configurato."}, status_code=503)
        form_data = await request.form()
        try:
            student_info = PersonalInfo(
                surname_hash=self.crypto_utils.sha256_hash_string(form_data.get("cognome", "")), name_hash=self.crypto_utils.sha256_hash_string(form_data.get("nome", "")),
                birth_date_hash=self.crypto_utils.sha256_hash_string("01/01/2000"), student_id_hash=self.crypto_utils.sha256_hash_string(form_data.get("matricola", "")),
                pseudonym=f"student_{form_data.get('nome','').lower()}"
            )
            study_period = StudyPeriod(
                start_date=datetime.datetime.fromisoformat(form_data.get("inizio_periodo")), end_date=datetime.datetime.fromisoformat(form_data.get("fine_periodo")),
                study_type=StudyType.ERASMUS, academic_year="2024/2025"
            )
            courses = [Course(
                course_name=form_data.get("nome_corso", "Corso di Prova"), course_code="DEMO-01", isced_code="0613",
                grade=ExamGrade(score=f"{form_data.get('voto', '18')}/30", passed=True, grade_system=GradeSystem.ITALIAN_30),
                exam_date=datetime.datetime.now(datetime.timezone.utc), ects_credits=int(form_data.get("cfu", 0)), professor="Prof. Demo"
            )]
            request_id = self.issuer.create_issuance_request(
                student_info=student_info, study_period=study_period,
                host_university=University(name="Université de Rennes", country="FR", city="Rennes"),
                study_program=StudyProgram(name="Ingegneria Informatica", isced_code="0613", eqf_level=EQFLevel.LEVEL_7, program_type="Laurea Magistrale", field_of_study="Informatica"),
                courses=courses, requested_by=user.user_id
            )
            result = self.issuer.process_issuance_request(request_id)
            if result.success:
                return JSONResponse({"success": True, "message": "Credenziale emessa e firmata!", "credential_id": result.credential_id})
            else:
                return JSONResponse({"success": False, "message": "Errore durante l'emissione.", "errors": result.errors}, status_code=400)
        except Exception as e:
            return JSONResponse({"success": False, "message": f"Errore server: {str(e)}"}, status_code=500)

    async def render_verification_page(self, request: Request):
        user = self.get_current_user(request)
        if not user: return RedirectResponse(url="/login")
        return self.templates.TemplateResponse("verification.html", {"request": request, "user": user, "title": "Verifica"})

    async def render_integration_page(self, request: Request):
        user = self.get_current_user(request)
        if not user: return RedirectResponse(url="/login")
        return self.templates.TemplateResponse("integration.html", {"request": request, "user": user, "integration_stats": self.mock_data.get("integration_stats"), "title": "Integrazione"})

    async def render_monitoring_page(self, request: Request):
        user = self.get_current_user(request)
        if not user: return RedirectResponse(url="/login")
        return self.templates.TemplateResponse("monitoring.html", {"request": request, "user": user, "system_health": self.mock_data.get("system_health"), "title": "Monitoring"})

    async def render_testing_page(self, request: Request):
        user = self.get_current_user(request)
        if not user or "admin" not in user.permissions: raise HTTPException(403)
        return self.templates.TemplateResponse("testing.html", {"request": request, "user": user, "title": "Testing"})

    def _get_dashboard_stats(self) -> DashboardStats:
        total_issued = len(self.issuer.list_credentials()) if self.issuer else 0
        return DashboardStats(
            total_credentials_issued=total_issued, total_credentials_verified=45, pending_verifications=12, 
            active_students=128, total_credits_processed=2450, success_rate=94.5, 
            last_updated=datetime.datetime.now(datetime.timezone.utc)
        )
    
    def _initialize_mock_data(self) -> Dict[str, Any]:
        """Inizializza dati mock completi per le sezioni non ancora implementate."""
        return {
            "integration_stats": {
                "connected_systems": 3, "pending_mappings": 5,
                "auto_approved": 23, "manual_review": 7
            },
            "system_health": {
                "blockchain_status": "connected", "database_status": "healthy",
                "api_response_time": "120ms", "uptime": "99.9%"
            }
        }

dashboard_instance = AcademicCredentialsDashboard()
app = dashboard_instance.app

if __name__ == "__main__":
    print("="*60)
    print("Avvio del Server Web per la Gestione delle Credenziali Accademiche")
    print(f"I moduli del progetto sono stati caricati: {'Sì' if MODULES_LOADED else 'NO'}")
    print("="*60)
    uvicorn.run(app, host="127.0.0.1", port=8000)