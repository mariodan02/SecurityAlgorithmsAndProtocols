# =============================================================================
# FASE 9: INTERFACCE E DEPLOYMENT - WEB DASHBOARD (VERSIONE FINALE CON PWD SEMPLICE)
# File: src/web/dashboard.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import json
import datetime
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Any

# FastAPI e web dependencies
from fastapi import FastAPI, Request, HTTPException, Depends, Form, Body
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.cors import CORSMiddleware

# Pydantic per validazione
from pydantic import BaseModel

# Import della logica di business
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))

from wallet import (
    AcademicStudentWallet, WalletConfiguration, PresentationManager,
    DisclosureLevel, PresentationFormat
)
from credentials import CredentialFactory

# Percorsi robusti basati sulla posizione del file
SRC_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = SRC_DIR / "web" / "static"
TEMPLATES_DIR = SRC_DIR / "web" / "templates"
PRESENTATIONS_DIR = STATIC_DIR / "presentations"

# =============================================================================
# MODELLI DATI E UTENTI DEMO
# =============================================================================

class UserSession(BaseModel):
    user_id: str
    display_name: str
    role: str
    permissions: List[str]

SIMPLE_PASSWORD = "Unisa2025"

DEMO_USERS = {
    "issuer_rennes": {"password": SIMPLE_PASSWORD, "role": "issuer", "display_name": "Université de Rennes (Issuer)", "permissions": ["read", "verify", "issue"]},
    "verifier_unisa": {"password": SIMPLE_PASSWORD, "role": "verifier", "display_name": "Università di Salerno (Verifier)", "permissions": ["read", "verify"]},
    "studente_mariorossi": {"password": SIMPLE_PASSWORD, "role": "student", "display_name": "Mario Rossi (Studente Unisa)", "permissions": ["read_wallet", "disclose"]}
}

# =============================================================================
# CLASSE PRINCIPALE DELLA DASHBOARD WEB
# =============================================================================

class AcademicCredentialsDashboard:
    """Orchestra l'applicazione web, delegando la logica di business."""

    def __init__(self):
        self.app = FastAPI(title="Academic Credentials Dashboard", version="2.2.0")
        self.secret_key = "una_chiave_segreta_molto_piu_robusta_in_produzione"
        self.templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
        self.sessions: Dict[str, UserSession] = {}
        
        self.student_wallet = self._initialize_demo_wallet()
        if self.student_wallet:
             self.presentation_manager = PresentationManager(self.student_wallet)
             print("✅ Wallet e Presentation Manager inizializzati con successo.")
        else:
            print("❌ INIZIALIZZAZIONE FALLITA. Impossibile creare Presentation Manager.")
            self.presentation_manager = None

        self._setup_middleware_and_static_files()
        self._setup_routes()

        print("🌐 Academic Credentials Dashboard (v2.2.0) inizializzato.")

    def _initialize_demo_wallet(self) -> Optional[AcademicStudentWallet]:
        """Crea e popola un wallet demo in modo robusto."""
        try:
            wallet_path = SRC_DIR.parent / "demo_wallet" / "mario_rossi"
            config = WalletConfiguration(
                wallet_name="Mario Rossi Demo Wallet",
                storage_path=str(wallet_path)
            )
            wallet = AcademicStudentWallet(config)
            
            if not wallet.wallet_file.exists():
                print("Tentativo di creare un nuovo wallet demo...")
                if not wallet.create_wallet(SIMPLE_PASSWORD):
                    print("ERRORE CRITICO: Impossibile creare il wallet demo.")
                    return None
            
            if wallet.status != "unlocked":
                if not wallet.unlock_wallet(SIMPLE_PASSWORD):
                    print("ERRORE CRITICO: Impossibile sbloccare il wallet demo.")
                    return None

            if not wallet.list_credentials():
                print("Popolando il wallet demo con credenziali di esempio...")
                cred1 = CredentialFactory.create_sample_credential()
                cred1.issuer.name = "Université de Rennes"
                cred1.host_university.name = "Università di Salerno"
                wallet.add_credential(cred1, tags=["erasmus", "francia", "2025"])
            
            return wallet
        except Exception as e:
            print(f"ERRORE FATALE durante l'inizializzazione del wallet: {e}")
            return None

    def _setup_middleware_and_static_files(self):
        """Configura middleware e cartelle statiche."""
        self.app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
        self.app.add_middleware(SessionMiddleware, secret_key=self.secret_key)
        PRESENTATIONS_DIR.mkdir(exist_ok=True)
        self.app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    def _get_current_user(self, request: Request) -> Optional[UserSession]:
        session_id = request.session.get("session_id")
        return self.sessions.get(session_id)

    def _setup_routes(self):
        """Configura tutti gli endpoint dell'applicazione."""
        
        @self.app.get("/", response_class=HTMLResponse)
        async def home(request: Request):
            user = self._get_current_user(request)
            if user:
                return RedirectResponse(url="/wallet" if user.role == 'student' else "/dashboard", status_code=302)
            return self.templates.TemplateResponse("home.html", {"request": request, "title": "Home"})

        @self.app.get("/login", response_class=HTMLResponse)
        async def login_page(request: Request):
            return self.templates.TemplateResponse("login.html", {"request": request, "title": "Login"})

        @self.app.post("/login")
        async def login(request: Request, username: str = Form(...), password: str = Form(...)):
            user_data = DEMO_USERS.get(username)
            if user_data and user_data["password"] == password:
                session_id = str(uuid.uuid4())
                self.sessions[session_id] = UserSession(**user_data, user_id=username, login_time=datetime.datetime.utcnow())
                request.session["session_id"] = session_id
                return RedirectResponse(url="/wallet" if user_data["role"] == 'student' else "/dashboard", status_code=302)
            return self.templates.TemplateResponse("login.html", {"request": request, "title": "Login", "error": "Credenziali non valide"})

        @self.app.get("/logout")
        async def logout(request: Request):
            session_id = request.session.pop("session_id", None)
            if session_id in self.sessions:
                del self.sessions[session_id]
            return RedirectResponse(url="/", status_code=302)

        @self.app.get("/dashboard", response_class=HTMLResponse)
        async def dashboard(request: Request):
            user = self._get_current_user(request)
            if not user or user.role not in ['issuer', 'verifier']:
                return RedirectResponse(url="/login", status_code=302)
            return self.templates.TemplateResponse("dashboard.html", {"request": request, "user": user})

        @self.app.get("/wallet", response_class=HTMLResponse)
        async def student_wallet_page(request: Request):
            user = self._get_current_user(request)
            if not user or user.role != 'student':
                return RedirectResponse(url="/login", status_code=302)
            
            if not self.student_wallet:
                 raise HTTPException(status_code=500, detail="Il wallet dello studente non è stato inizializzato correttamente.")

            credentials_summary = self.student_wallet.list_credentials()
            return self.templates.TemplateResponse("student_wallet.html", {
                "request": request, "user": user, "title": "Il Mio Wallet",
                "credentials": credentials_summary
            })

        @self.app.post("/wallet/create-presentation", response_class=JSONResponse)
        async def create_presentation_endpoint(request: Request, payload: Dict[str, Any] = Body(...)):
            user = self._get_current_user(request)
            if not user or "disclose" not in user.permissions:
                return JSONResponse(status_code=403, content={"success": False, "message": "Accesso non autorizzato"})

            if not self.presentation_manager:
                return JSONResponse(status_code=500, content={"success": False, "message": "Il Presentation Manager non è disponibile."})

            try:
                purpose = payload.get("purpose")
                selected_items = payload.get("credentials", [])

                if not purpose or not selected_items:
                    return JSONResponse(status_code=400, content={"success": False, "message": "Scopo e selezione di almeno una credenziale sono obbligatori."})

                credential_selections = [{
                    "storage_id": item.get("credential_id"),
                    "disclosure_level": DisclosureLevel[item.get("disclosure_level", "standard").upper()]
                } for item in selected_items]
                
                presentation_id = self.presentation_manager.create_presentation(purpose=purpose, credential_selections=credential_selections)
                self.presentation_manager.sign_presentation(presentation_id)
                
                file_name = f"presentation_{presentation_id}.json"
                output_path = PRESENTATIONS_DIR / file_name
                self.presentation_manager.export_presentation(presentation_id, str(output_path), PresentationFormat.SIGNED_JSON)
                
                return JSONResponse(status_code=200, content={
                    "success": True, "message": "Presentazione firmata creata con successo!",
                    "download_link": f"/static/presentations/{file_name}"
                })

            except Exception as e:
                print(f"ERRORE CREAZIONE PRESENTAZIONE: {e}")
                return JSONResponse(status_code=500, content={"success": False, "message": f"Errore interno del server: {str(e)}"})


# --- Esposizione dell'app per Uvicorn ---
dashboard_instance = AcademicCredentialsDashboard()
app = dashboard_instance.app

if __name__ == "__main__":
    import uvicorn
    print("Avviando il server in modalità di sviluppo diretta...")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)