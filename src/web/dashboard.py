# =============================================================================
# FASE 9: INTERFACCE E DEPLOYMENT - WEB DASHBOARD (Versione Completa Corretta)
# File: web/dashboard.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import json
import uuid
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import asyncio

# FastAPI e web dependencies
from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

# Pydantic per validazione
from pydantic import BaseModel

# =============================================================================
# IMPORT DEI MODULI DEL PROGETTO E DELLA CONFIGURAZIONE PKI
# =============================================================================
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    # Moduli principali del sistema
    from credentials.models import AcademicCredential, CredentialFactory
    from credentials.issuer import AcademicCredentialIssuer
    from verification.verification_engine import CredentialVerificationEngine
    from pki.certificate_manager import CertificateManager

    # Import della funzione di setup per la PKI personalizzata
    from run_verificationCA import setup_validator_with_custom_pki
    print("✅ Moduli di sistema e configurazione PKI importati correttamente.")

except ImportError as e:
    print(f"⚠️  ERRORE IMPORT MODULI: {e}")
    print("   Assicurati che tutti i file necessari (come run_verificationCA.py) siano presenti in 'src/'.")
    # Imposta i moduli a None per evitare che il server si blocchi completamente all'avvio
    CredentialVerificationEngine = None
    CertificateManager = None
    setup_validator_with_custom_pki = None

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
    success_rate: float
    last_updated: datetime.datetime

# =============================================================================
# 2. CLASSE PRINCIPALE DEL WEB DASHBOARD
# =============================================================================

class AcademicCredentialsDashboard:
    
    def __init__(self):
        self.app = FastAPI(title="Academic Credentials Dashboard", version="1.0.0")
        
        # Configurazione base
        self.secret_key = "una_chiave_segreta_molto_sicura_da_cambiare"
        self.templates_dir = Path("./web/templates")
        self.static_dir = Path("./web/static")
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.static_dir.mkdir(parents=True, exist_ok=True)
        self.templates = Jinja2Templates(directory=str(self.templates_dir))
        
        # Inizializzazione componenti di sistema
        self._initialize_components()

        # Storage in memoria per la demo
        self.sessions: Dict[str, UserSession] = {}
        self.mock_data = self._initialize_mock_data()
        
        # Setup di FastAPI
        self._setup_middleware()
        self._setup_static_files()
        self._setup_routes()

    def _initialize_components(self):
        print("\n" + "="*50)
        print("INIZIALIZZAZIONE COMPONENTI DI SICUREZZA")
        print("="*50)
        
        self.issuer: Optional[AcademicCredentialIssuer] = None
        self.verification_engine: Optional[CredentialVerificationEngine] = None
        
        try:
            if CredentialVerificationEngine and CertificateManager and setup_validator_with_custom_pki:
                custom_validator = setup_validator_with_custom_pki()
                if custom_validator:
                    cert_manager = CertificateManager()
                    self.verification_engine = CredentialVerificationEngine("Dashboard Verifier", cert_manager)
                    self.verification_engine.credential_validator = custom_validator
                    print("\n👍 Motore di verifica AGGIORNATO con il validatore fidato.")
                else:
                    print("\n⚠️ ATTENZIONE: Impossibile creare il validatore personalizzato.")
            else:
                print("\n⚠️ ATTENZIONE: Moduli necessari non caricati. L'engine di verifica non sarà disponibile.")
        except Exception as e:
            print(f"🔥 ERRORE CRITICO durante l'inizializzazione: {e}")
            self.verification_engine = None
        
        print("="*50 + "\n")

    def _setup_middleware(self):
        self.app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
        self.app.add_middleware(SessionMiddleware, secret_key=self.secret_key)
    
    def _setup_static_files(self):
        self.app.mount("/static", StaticFiles(directory=str(self.static_dir)), name="static")
    
    def _get_current_user(self, request: Request) -> Optional[UserSession]:
        session_id = request.session.get("session_id")
        if session_id and session_id in self.sessions:
            user = self.sessions[session_id]
            user.last_activity = datetime.datetime.utcnow()
            return user
        return None

    def _setup_routes(self):
        # --- Route di Autenticazione e Home ---
        @self.app.get("/", response_class=HTMLResponse)
        async def home(request: Request):
            user = self._get_current_user(request)
            if user:
                return RedirectResponse(url="/wallet" if user.role == 'studente' else "/dashboard", status_code=302)
            return self.templates.TemplateResponse("home.html", {"request": request, "title": "Home"})

        @self.app.get("/login", response_class=HTMLResponse)
        async def login_page(request: Request):
            return self.templates.TemplateResponse("login.html", {"request": request, "title": "Login"})

        @self.app.post("/login")
        async def login(request: Request, username: str = Form(...), password: str = Form(...)):
            valid_users = {
                "studente_mariorossi": {"role": "studente", "university": "Università di Salerno"},
                "issuer_rennes": {"role": "issuer", "university": "Université de Rennes"},
                "verifier_unisa": {"role": "verifier", "university": "Università di Salerno"}
            }

            if username in valid_users and password == "Unisa2025":
                session_id = f"session_{uuid.uuid4()}"
                user_info = valid_users[username]
                self.sessions[session_id] = UserSession(
                    user_id=username, university_name=user_info["university"], role=user_info["role"],
                    permissions=["read", "share"] if user_info["role"] == "studente" else ["read", "write"],
                    login_time=datetime.datetime.utcnow(), last_activity=datetime.datetime.utcnow()
                )
                request.session["session_id"] = session_id
                
                redirect_url = "/wallet" if user_info["role"] == "studente" else "/dashboard"
                print(f"✅ Accesso per {username} (ruolo: {user_info['role']}). Reindirizzamento a {redirect_url}")
                return RedirectResponse(url=redirect_url, status_code=302)

            return self.templates.TemplateResponse("login.html", {"request": request, "error": "Credenziali non valide"})

        @self.app.get("/logout")
        async def logout(request: Request):
            request.session.pop("session_id", None)
            return RedirectResponse(url="/", status_code=302)

        # --- Route per lo Studente ---
        @self.app.get("/wallet", response_class=HTMLResponse)
        async def wallet_page(request: Request):
            user = self._get_current_user(request)
            if not user or user.role != "studente": return RedirectResponse(url="/login", status_code=302)
            return self.templates.TemplateResponse("student_wallet.html", {
                "request": request, "user": user, "title": "My Wallet", "credentials": self.mock_data.get("wallet_credentials", [])
            })

        # --- Route per Personale Universitario ---
        @self.app.get("/dashboard", response_class=HTMLResponse)
        async def dashboard(request: Request):
            user = self._get_current_user(request)
            if not user or user.role == "studente": return RedirectResponse(url="/login", status_code=302)
            stats = self._get_dashboard_stats()
            return self.templates.TemplateResponse("dashboard.html", {"request": request, "user": user, "stats": stats, "title": "Dashboard"})
        
        @self.app.get("/credentials", response_class=HTMLResponse)
        async def credentials_page(request: Request):
            user = self._get_current_user(request)
            if not user or user.role == "studente": return RedirectResponse(url="/login", status_code=302)
            return self.templates.TemplateResponse("credentials.html", {"request": request, "user": user})

        @self.app.get("/verification", response_class=HTMLResponse)
        async def verification_page(request: Request):
            user = self._get_current_user(request)
            if not user or user.role == "studente": return RedirectResponse(url="/login", status_code=302)
            return self.templates.TemplateResponse("verification.html", {"request": request, "user": user})

    def _get_dashboard_stats(self) -> DashboardStats:
        return DashboardStats(
            total_credentials_issued=self.mock_data["issued_credentials"],
            total_credentials_verified=45,
            pending_verifications=3,
            success_rate=94.5,
            last_updated=datetime.datetime.utcnow()
        )
    
    def _initialize_mock_data(self) -> Dict[str, Any]:
        return { 
            "issued_credentials": 12,
            "wallet_credentials": [
                {"id": "cred_france_123", "issuer": "Université de Rennes", "courses": 3, "status": "Attiva"},
                {"id": "cred_germany_456", "issuer": "TU München", "courses": 4, "status": "Attiva"},
            ]
        }

# =============================================================================
# 3. PUNTO DI INGRESSO PER UVICORN
# =============================================================================

dashboard_app_instance = AcademicCredentialsDashboard()
app = dashboard_app_instance.app

if __name__ == "__main__":
    print("🌐 Avvio Web Dashboard in modalità standalone (per debug)...")
    dashboard_app_instance.run(host="127.0.0.1", port=8000)