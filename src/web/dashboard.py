# =============================================================================
# FASE 9: INTERFACCE E DEPLOYMENT - WEB DASHBOARD (CORRETTO E PULITO)
# File: web/dashboard.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import json
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import asyncio
import sys

# --- Blocco di importazione robusto per i moduli del progetto ---
try:
    # Trova la directory 'src' risalendo dall'attuale file
    src_path = Path(__file__).resolve().parent.parent
    if src_path.name != 'src':
        project_root = Path(__file__).resolve().parent.parent.parent
        src_path = project_root / 'src'
        if not src_path.exists():
             src_path = Path.cwd() / 'src'

    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))
    
    print(f"✅ Percorso 'src' aggiunto al path: {src_path}")

    from credentials.models import AcademicCredential, CredentialFactory
    from credentials.issuer import AcademicCredentialIssuer
    from verification.verification_engine import CredentialVerificationEngine, VerificationLevel
    from verification.university_integration import UniversityIntegrationManager
    from wallet.presentation import PresentationManager
    # --- MODIFICA CHIAVE: Import dal file corretto 'blockchain_client' ---
    from blockchain.blockchain_client import RevocationRegistryManager
    from testing.end_to_end_testing import EndToEndTestManager
    MODULES_LOADED = True
except ImportError as e:
    print(f"⚠️  Import dei moduli principali fallito: {e}")
    print(f"   Verifica che la struttura del progetto sia corretta e che i moduli siano presenti.")
    MODULES_LOADED = False
# --- Fine del blocco di importazione ---


# FastAPI e web dependencies
from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn

# Pydantic per validazione
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware


# =============================================================================
# 1. MODELLI DATI WEB
# =============================================================================

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
    active_students: int
    total_credits_processed: int
    success_rate: float
    last_updated: datetime.datetime

# =============================================================================
# 2. WEB DASHBOARD PRINCIPALE
# =============================================================================

class AcademicCredentialsDashboard:
    """Dashboard web per gestione credenziali accademiche"""
    
    def __init__(self):
        self.app = FastAPI(title="Academic Credentials Dashboard", version="1.0.0")
        self.secret_key = "demo_secret_key_change_in_production"
        self.templates_dir = Path(__file__).resolve().parent / "templates"
        self.static_dir = Path(__file__).resolve().parent / "static"
        
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.static_dir.mkdir(parents=True, exist_ok=True)
        
        self.templates = Jinja2Templates(directory=str(self.templates_dir))
        
        if MODULES_LOADED:
            self.issuer: Optional[AcademicCredentialIssuer] = None
            self.verification_engine: Optional[CredentialVerificationEngine] = None
            self.integration_manager: Optional[UniversityIntegrationManager] = None
            self.test_manager: Optional[EndToEndTestManager] = None
        
        self.sessions: Dict[str, UserSession] = {}
        self.mock_data = self._initialize_mock_data()
        
        self._setup_middleware()
        self._setup_static_files()
        self._setup_routes()
        
        print("🌐 Academic Credentials Dashboard inizializzato")
    
    def _setup_middleware(self):
        self.app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
        self.app.add_middleware(SessionMiddleware, secret_key=self.secret_key)
    
    def _setup_static_files(self):
        self.app.mount("/static", StaticFiles(directory=str(self.static_dir)), name="static")
    
    def _setup_routes(self):
        # Home e autenticazione
        @self.app.get("/", response_class=HTMLResponse)
        async def home(request: Request): return await self._render_home(request)
        @self.app.get("/login", response_class=HTMLResponse)
        async def login_page(request: Request): return await self._render_login(request)
        @self.app.post("/login")
        async def login(request: Request, username: str = Form(...), password: str = Form(...)): return await self._handle_login(request, username, password)
        @self.app.get("/logout")
        async def logout(request: Request): return await self._handle_logout(request)
        
        # Pagine principali
        @self.app.get("/dashboard", response_class=HTMLResponse)
        async def dashboard(request: Request): return await self._render_dashboard(request)
        @self.app.get("/credentials", response_class=HTMLResponse)
        async def credentials_page(request: Request): return await self._render_credentials(request)
        @self.app.get("/credentials/issue", response_class=HTMLResponse)
        async def issue_credential_page(request: Request): return await self._render_issue_credential(request)
        @self.app.post("/credentials/issue")
        async def issue_credential(request: Request): return await self._handle_issue_credential(request)
        @self.app.get("/verification", response_class=HTMLResponse)
        async def verification_page(request: Request): return await self._render_verification(request)
        @self.app.get("/integration", response_class=HTMLResponse)
        async def integration_page(request: Request): return await self._render_integration(request)
        @self.app.get("/monitoring", response_class=HTMLResponse)
        async def monitoring_page(request: Request): return await self._render_monitoring(request)
        @self.app.get("/testing", response_class=HTMLResponse)
        async def testing_page(request: Request): return await self._render_testing(request)

    # --- HANDLERS ---
    
    async def _render_home(self, request: Request):
        if request.session.get("session_id") in self.sessions:
            return RedirectResponse(url="/dashboard", status_code=302)
        return self.templates.TemplateResponse("home.html", {"request": request, "title": "Home"})

    async def _render_login(self, request: Request):
        return self.templates.TemplateResponse("login.html", {"request": request, "title": "Login"})

    async def _handle_login(self, request: Request, username: str, password: str):
        if username in ["admin", "issuer", "verifier"] and password == "demo123":
            # --- MODIFICA: Utilizzo di datetime.now(timezone.utc) ---
            utc_now = datetime.datetime.now(datetime.timezone.utc)
            session_id = f"session_{utc_now.timestamp()}"
            
            permissions = []
            if username == "admin": permissions = ["read", "write", "admin"]
            elif username == "issuer": permissions = ["read", "write"]
            else: permissions = ["read"]
            
            user_session = UserSession(
                user_id=username, university_name="Demo University", role=username, permissions=permissions,
                login_time=utc_now, last_activity=utc_now
            )
            self.sessions[session_id] = user_session
            request.session["session_id"] = session_id
            return RedirectResponse(url="/dashboard", status_code=302)
        
        return self.templates.TemplateResponse("login.html", {"request": request, "title": "Login", "error": "Credenziali non valide"})

    async def _handle_logout(self, request: Request):
        session_id = request.session.get("session_id")
        if session_id and session_id in self.sessions:
            del self.sessions[session_id]
        request.session.clear()
        return RedirectResponse(url="/", status_code=302)

    def _get_current_user(self, request: Request) -> Optional[UserSession]:
        session_id = request.session.get("session_id")
        if session_id and session_id in self.sessions:
            user = self.sessions[session_id]
            user.last_activity = datetime.datetime.now(datetime.timezone.utc)
            return user
        return None

    async def _render_dashboard(self, request: Request):
        user = self._get_current_user(request)
        if not user: return RedirectResponse(url="/login", status_code=302)
        stats = await self._get_dashboard_stats()
        return self.templates.TemplateResponse("dashboard.html", {"request": request, "user": user, "stats": stats, "title": "Dashboard"})

    async def _render_credentials(self, request: Request):
        user = self._get_current_user(request)
        if not user: return RedirectResponse(url="/login", status_code=302)
        return self.templates.TemplateResponse("credentials.html", {"request": request, "user": user, "credentials": self.mock_data["issued_credentials"], "title": "Gestione Credenziali"})

    async def _render_issue_credential(self, request: Request):
        user = self._get_current_user(request)
        if not user: return RedirectResponse(url="/login", status_code=302)
        if "write" not in user.permissions: raise HTTPException(status_code=403, detail="Permessi insufficienti")
        return self.templates.TemplateResponse("issue_credential.html", {"request": request, "user": user, "title": "Emissione Credenziale"})

    async def _handle_issue_credential(self, request: Request):
        user = self._get_current_user(request)
        if not user or "write" not in user.permissions: raise HTTPException(status_code=403, detail="Non autorizzato")
        form_data = await request.form()
        try:
            if not MODULES_LOADED: raise ImportError("Modulo 'credentials' non caricato.")
            credential = CredentialFactory.create_sample_credential()
            if form_data.get("student_name"): credential.subject.pseudonym = form_data["student_name"]
            
            credential_data = {
                "credential_id": str(credential.metadata.credential_id), "student_name": form_data.get("student_name", "Unknown"),
                "issued_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "issued_by": user.user_id, "status": "active"
            }
            self.mock_data["issued_credentials"].append(credential_data)
            return JSONResponse({"success": True, "message": "Credenziale emessa con successo", "credential_id": credential_data["credential_id"]})
        except Exception as e:
            return JSONResponse({"success": False, "message": f"Errore emissione: {e}"}, status_code=400)

    # (altri handler rimangono simili)
    async def _render_verification(self, request: Request):
        user = self._get_current_user(request)
        if not user: return RedirectResponse(url="/login", status_code=302)
        return self.templates.TemplateResponse("verification.html", {"request": request, "user": user, "title": "Verifica"})
    
    async def _render_integration(self, request: Request):
        user = self._get_current_user(request)
        if not user: return RedirectResponse(url="/login", status_code=302)
        return self.templates.TemplateResponse("integration.html", {"request": request, "user": user, "title": "Integrazione"})
        
    async def _render_monitoring(self, request: Request):
        user = self._get_current_user(request)
        if not user: return RedirectResponse(url="/login", status_code=302)
        return self.templates.TemplateResponse("monitoring.html", {"request": request, "user": user, "title": "Monitoring"})

    async def _render_testing(self, request: Request):
        user = self._get_current_user(request)
        if not user: return RedirectResponse(url="/login", status_code=302)
        if user.role != "admin": raise HTTPException(status_code=403, detail="Solo admin")
        return self.templates.TemplateResponse("testing.html", {"request": request, "user": user, "title": "Testing"})

    async def _get_dashboard_stats(self) -> DashboardStats:
        return DashboardStats(
            total_credentials_issued=len(self.mock_data["issued_credentials"]), total_credentials_verified=45,
            pending_verifications=len(self.mock_data["pending_verifications"]), active_students=128,
            total_credits_processed=2450, success_rate=94.5,
            last_updated=datetime.datetime.now(datetime.timezone.utc)
        )

    def _initialize_mock_data(self) -> Dict[str, Any]:
        return {
            "issued_credentials": [
                {"credential_id": "cred_001", "student_name": "Mario Rossi", "issued_at": "2024-12-15T10:30:00Z", "issued_by": "admin", "status": "active"},
                {"credential_id": "cred_002", "student_name": "Anna Bianchi", "issued_at": "2024-12-14T15:45:00Z", "issued_by": "issuer", "status": "active"}
            ],
            "pending_verifications": [{"verification_id": "ver_001", "student_name": "Giuseppe Verdi", "submitted_at": "2024-12-15T14:20:00Z", "purpose": "Credit Recognition", "status": "pending"}]
        }
    
    def run(self, host: str = "0.0.0.0", port: int = 8000):
        print(f"🚀 Avviando dashboard su http://{host}:{port}")
        print(f"   Login demo: admin/demo123, issuer/demo123, verifier/demo123")
        uvicorn.run(self.app, host=host, port=port)

# =============================================================================
# 3. MAIN
# =============================================================================

if __name__ == "__main__":
    print("🌐" * 50)
    print("ACADEMIC CREDENTIALS WEB DASHBOARD")
    print("🌐" * 50)
    
    dashboard = AcademicCredentialsDashboard()
    dashboard.run()