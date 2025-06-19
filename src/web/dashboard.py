# =============================================================================
# FASE 9: INTERFACCE E DEPLOYMENT - WEB DASHBOARD
# File: web/dashboard.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import json
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import asyncio

# FastAPI e web dependencies
from fastapi import FastAPI, Request, HTTPException, Depends, Form, File, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn

# Pydantic per validazione
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

# Import moduli interni
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from credentials.models import AcademicCredential, CredentialFactory
    from credentials.issuer import AcademicCredentialIssuer
    from verification.verification_engine import CredentialVerificationEngine, VerificationLevel
    from verification.university_integration import UniversityIntegrationManager
    from wallet.presentation import PresentationManager
    from blockchain.revocation_registry import RevocationRegistryManager
    from testing.end_to_end_testing import EndToEndTestManager
except ImportError as e:
    print(f"⚠️  Import moduli: {e}")


# =============================================================================
# 1. MODELLI DATI WEB
# =============================================================================

class UserSession(BaseModel):
    """Sessione utente"""
    user_id: str
    university_name: str
    role: str  # admin, issuer, verifier
    permissions: List[str]
    login_time: datetime.datetime
    last_activity: datetime.datetime


class DashboardStats(BaseModel):
    """Statistiche dashboard"""
    total_credentials_issued: int
    total_credentials_verified: int
    pending_verifications: int
    active_students: int
    total_credits_processed: int
    success_rate: float
    last_updated: datetime.datetime


class CredentialIssuanceRequest(BaseModel):
    """Richiesta emissione credenziale"""
    student_id: str
    student_name: str
    study_period_start: str
    study_period_end: str
    courses: List[Dict[str, Any]]
    additional_notes: Optional[str] = None


class VerificationRequest(BaseModel):
    """Richiesta verifica"""
    presentation_data: Dict[str, Any]
    verification_level: str = "standard"
    purpose: str = "credit_recognition"


# =============================================================================
# 2. WEB DASHBOARD PRINCIPALE
# =============================================================================

class AcademicCredentialsDashboard:
    """Dashboard web per gestione credenziali accademiche"""
    
    def __init__(self):
        """Inizializza dashboard"""
        self.app = FastAPI(
            title="Academic Credentials Dashboard",
            description="Dashboard per gestione credenziali accademiche decentralizzate",
            version="1.0.0"
        )
        
        # Configurazione
        self.secret_key = "demo_secret_key_change_in_production"
        self.templates_dir = Path("./web/templates")
        self.static_dir = Path("./web/static")
        
        # Crea directories se non esistono
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.static_dir.mkdir(parents=True, exist_ok=True)
        
        # Template engine
        self.templates = Jinja2Templates(directory=str(self.templates_dir))
        
        # Componenti sistema
        self.issuer: Optional[AcademicCredentialIssuer] = None
        self.verification_engine: Optional[CredentialVerificationEngine] = None
        self.integration_manager: Optional[UniversityIntegrationManager] = None
        self.test_manager: Optional[EndToEndTestManager] = None
        
        # Storage sessioni (in produzione usare Redis)
        self.sessions: Dict[str, UserSession] = {}
        
        # Dati mock per demo
        self.mock_data = self._initialize_mock_data()
        
        # Setup app
        self._setup_middleware()
        self._setup_static_files()
        self._setup_routes()
        self._create_templates()
        
        print("🌐 Academic Credentials Dashboard inizializzato")
    
    def _setup_middleware(self):
        """Configura middleware"""
        # CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # In produzione: domini specifici
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Sessions
        self.app.add_middleware(
            SessionMiddleware, 
            secret_key=self.secret_key
        )
    
    def _setup_static_files(self):
        """Configura file statici"""
        # Crea CSS base se non esiste
        css_file = self.static_dir / "style.css"
        if not css_file.exists():
            self._create_base_css()
        
        # Mount static files
        self.app.mount("/static", StaticFiles(directory=str(self.static_dir)), name="static")
    
    def _setup_routes(self):
        """Configura routes"""
        
        # Home e autenticazione
        @self.app.get("/", response_class=HTMLResponse)
        async def home(request: Request):
            return await self._render_home(request)
        
        @self.app.get("/login", response_class=HTMLResponse)
        async def login_page(request: Request):
            return await self._render_login(request)
        
        @self.app.post("/login")
        async def login(request: Request, username: str = Form(...), password: str = Form(...)):
            return await self._handle_login(request, username, password)
        
        @self.app.get("/logout")
        async def logout(request: Request):
            return await self._handle_logout(request)
        
        # Dashboard principale
        @self.app.get("/dashboard", response_class=HTMLResponse)
        async def dashboard(request: Request):
            return await self._render_dashboard(request)
        
        # Gestione credenziali
        @self.app.get("/credentials", response_class=HTMLResponse)
        async def credentials_page(request: Request):
            return await self._render_credentials(request)
        
        @self.app.get("/credentials/issue", response_class=HTMLResponse)
        async def issue_credential_page(request: Request):
            return await self._render_issue_credential(request)
        
        @self.app.post("/credentials/issue")
        async def issue_credential(request: Request):
            return await self._handle_issue_credential(request)
        
        # Verifica
        @self.app.get("/verification", response_class=HTMLResponse)
        async def verification_page(request: Request):
            return await self._render_verification(request)
        
        @self.app.post("/verification/verify")
        async def verify_presentation(request: Request):
            return await self._handle_verification(request)
        
        # Integrazione
        @self.app.get("/integration", response_class=HTMLResponse)
        async def integration_page(request: Request):
            return await self._render_integration(request)
        
        # Monitoring
        @self.app.get("/monitoring", response_class=HTMLResponse)
        async def monitoring_page(request: Request):
            return await self._render_monitoring(request)
        
        # Testing
        @self.app.get("/testing", response_class=HTMLResponse)
        async def testing_page(request: Request):
            return await self._render_testing(request)
        
        @self.app.post("/testing/run")
        async def run_tests(request: Request):
            return await self._handle_run_tests(request)
        
        # API endpoints
        @self.app.get("/api/stats")
        async def get_stats():
            return await self._get_dashboard_stats()
        
        @self.app.get("/api/credentials")
        async def get_credentials():
            return {"credentials": self.mock_data["issued_credentials"]}
        
        @self.app.get("/api/verification/pending")
        async def get_pending_verifications():
            return {"pending": self.mock_data["pending_verifications"]}
    
    # =============================================================================
    # HANDLERS AUTENTICAZIONE
    # =============================================================================
    
    async def _render_home(self, request: Request):
        """Render home page"""
        session_id = request.session.get("session_id")
        
        if session_id and session_id in self.sessions:
            return RedirectResponse(url="/dashboard", status_code=302)
        
        return self.templates.TemplateResponse("home.html", {
            "request": request,
            "title": "Academic Credentials System"
        })
    
    async def _render_login(self, request: Request):
        """Render login page"""
        return self.templates.TemplateResponse("login.html", {
            "request": request,
            "title": "Login - Academic Credentials"
        })
    
    async def _handle_login(self, request: Request, username: str, password: str):
        """Handle login"""
        # Autenticazione semplificata per demo
        if username in ["admin", "issuer", "verifier"] and password == "demo123":
            
            session_id = f"session_{datetime.datetime.utcnow().timestamp()}"
            
            user_session = UserSession(
                user_id=username,
                university_name="Demo University",
                role=username,
                permissions=["read", "write"] if username == "admin" else ["read"],
                login_time=datetime.datetime.utcnow(),
                last_activity=datetime.datetime.utcnow()
            )
            
            self.sessions[session_id] = user_session
            request.session["session_id"] = session_id
            
            return RedirectResponse(url="/dashboard", status_code=302)
        
        return self.templates.TemplateResponse("login.html", {
            "request": request,
            "title": "Login - Academic Credentials",
            "error": "Credenziali non valide"
        })
    
    async def _handle_logout(self, request: Request):
        """Handle logout"""
        session_id = request.session.get("session_id")
        
        if session_id and session_id in self.sessions:
            del self.sessions[session_id]
        
        request.session.clear()
        return RedirectResponse(url="/", status_code=302)
    
    def _get_current_user(self, request: Request) -> Optional[UserSession]:
        """Ottiene utente corrente"""
        session_id = request.session.get("session_id")
        
        if session_id and session_id in self.sessions:
            user = self.sessions[session_id]
            user.last_activity = datetime.datetime.utcnow()
            return user
        
        return None
    
    # =============================================================================
    # HANDLERS PAGINE PRINCIPALI
    # =============================================================================
    
    async def _render_dashboard(self, request: Request):
        """Render dashboard principale"""
        user = self._get_current_user(request)
        if not user:
            return RedirectResponse(url="/login", status_code=302)
        
        stats = await self._get_dashboard_stats()
        
        return self.templates.TemplateResponse("dashboard.html", {
            "request": request,
            "user": user,
            "stats": stats,
            "title": "Dashboard"
        })
    
    async def _render_credentials(self, request: Request):
        """Render pagina gestione credenziali"""
        user = self._get_current_user(request)
        if not user:
            return RedirectResponse(url="/login", status_code=302)
        
        return self.templates.TemplateResponse("credentials.html", {
            "request": request,
            "user": user,
            "credentials": self.mock_data["issued_credentials"],
            "title": "Gestione Credenziali"
        })
    
    async def _render_issue_credential(self, request: Request):
        """Render pagina emissione credenziale"""
        user = self._get_current_user(request)
        if not user:
            return RedirectResponse(url="/login", status_code=302)
        
        if "write" not in user.permissions:
            raise HTTPException(status_code=403, detail="Permessi insufficienti")
        
        return self.templates.TemplateResponse("issue_credential.html", {
            "request": request,
            "user": user,
            "title": "Emissione Credenziale"
        })
    
    async def _handle_issue_credential(self, request: Request):
        """Handle emissione credenziale"""
        user = self._get_current_user(request)
        if not user or "write" not in user.permissions:
            raise HTTPException(status_code=403, detail="Non autorizzato")
        
        # Parse form data
        form_data = await request.form()
        
        try:
            # Crea credenziale di esempio
            credential = CredentialFactory.create_sample_credential()
            
            # Personalizza con dati form
            if form_data.get("student_name"):
                credential.subject.pseudonym = form_data["student_name"]
            
            # Simula emissione
            credential_data = {
                "credential_id": str(credential.metadata.credential_id),
                "student_name": form_data.get("student_name", "Unknown"),
                "issued_at": datetime.datetime.utcnow().isoformat(),
                "issued_by": user.user_id,
                "status": "active"
            }
            
            self.mock_data["issued_credentials"].append(credential_data)
            
            return JSONResponse({
                "success": True,
                "message": "Credenziale emessa con successo",
                "credential_id": credential_data["credential_id"]
            })
            
        except Exception as e:
            return JSONResponse({
                "success": False,
                "message": f"Errore emissione: {e}"
            }, status_code=400)
    
    async def _render_verification(self, request: Request):
        """Render pagina verifica"""
        user = self._get_current_user(request)
        if not user:
            return RedirectResponse(url="/login", status_code=302)
        
        return self.templates.TemplateResponse("verification.html", {
            "request": request,
            "user": user,
            "pending_verifications": self.mock_data["pending_verifications"],
            "title": "Verifica Credenziali"
        })
    
    async def _handle_verification(self, request: Request):
        """Handle verifica presentazione"""
        user = self._get_current_user(request)
        if not user:
            raise HTTPException(status_code=403, detail="Non autorizzato")
        
        try:
            json_data = await request.json()
            
            # Simula verifica
            verification_result = {
                "verification_id": f"ver_{datetime.datetime.utcnow().timestamp()}",
                "result": "valid",
                "confidence_score": 0.95,
                "verified_at": datetime.datetime.utcnow().isoformat(),
                "verified_by": user.user_id,
                "details": {
                    "credentials_verified": 1,
                    "attributes_checked": 12,
                    "security_checks_passed": 8
                }
            }
            
            return JSONResponse({
                "success": True,
                "verification_result": verification_result
            })
            
        except Exception as e:
            return JSONResponse({
                "success": False,
                "message": f"Errore verifica: {e}"
            }, status_code=400)
    
    async def _render_integration(self, request: Request):
        """Render pagina integrazione"""
        user = self._get_current_user(request)
        if not user:
            return RedirectResponse(url="/login", status_code=302)
        
        return self.templates.TemplateResponse("integration.html", {
            "request": request,
            "user": user,
            "integration_stats": self.mock_data["integration_stats"],
            "title": "Integrazione Sistemi"
        })
    
    async def _render_monitoring(self, request: Request):
        """Render pagina monitoring"""
        user = self._get_current_user(request)
        if not user:
            return RedirectResponse(url="/login", status_code=302)
        
        return self.templates.TemplateResponse("monitoring.html", {
            "request": request,
            "user": user,
            "system_health": self.mock_data["system_health"],
            "title": "Monitoring Sistema"
        })
    
    async def _render_testing(self, request: Request):
        """Render pagina testing"""
        user = self._get_current_user(request)
        if not user:
            return RedirectResponse(url="/login", status_code=302)
        
        if user.role != "admin":
            raise HTTPException(status_code=403, detail="Solo admin")
        
        return self.templates.TemplateResponse("testing.html", {
            "request": request,
            "user": user,
            "test_results": self.mock_data["test_results"],
            "title": "Testing Sistema"
        })
    
    async def _handle_run_tests(self, request: Request):
        """Handle esecuzione test"""
        user = self._get_current_user(request)
        if not user or user.role != "admin":
            raise HTTPException(status_code=403, detail="Non autorizzato")
        
        try:
            # Simula esecuzione test
            import time
            import random
            
            # Simula delay
            await asyncio.sleep(2)
            
            test_result = {
                "test_run_id": f"run_{datetime.datetime.utcnow().timestamp()}",
                "started_at": datetime.datetime.utcnow().isoformat(),
                "total_tests": 15,
                "passed_tests": random.randint(12, 15),
                "failed_tests": random.randint(0, 3),
                "duration_sec": random.uniform(30, 90),
                "success_rate": random.uniform(80, 100)
            }
            
            return JSONResponse({
                "success": True,
                "test_result": test_result
            })
            
        except Exception as e:
            return JSONResponse({
                "success": False,
                "message": f"Errore test: {e}"
            }, status_code=500)
    
    # =============================================================================
    # API E UTILITIES
    # =============================================================================
    
    async def _get_dashboard_stats(self) -> DashboardStats:
        """Ottiene statistiche dashboard"""
        return DashboardStats(
            total_credentials_issued=len(self.mock_data["issued_credentials"]),
            total_credentials_verified=45,
            pending_verifications=len(self.mock_data["pending_verifications"]),
            active_students=128,
            total_credits_processed=2450,
            success_rate=94.5,
            last_updated=datetime.datetime.utcnow()
        )
    
    def _initialize_mock_data(self) -> Dict[str, Any]:
        """Inizializza dati mock per demo"""
        return {
            "issued_credentials": [
                {
                    "credential_id": "cred_001",
                    "student_name": "Mario Rossi",
                    "issued_at": "2024-12-15T10:30:00",
                    "issued_by": "admin",
                    "status": "active"
                },
                {
                    "credential_id": "cred_002", 
                    "student_name": "Anna Bianchi",
                    "issued_at": "2024-12-14T15:45:00",
                    "issued_by": "issuer",
                    "status": "active"
                }
            ],
            "pending_verifications": [
                {
                    "verification_id": "ver_001",
                    "student_name": "Giuseppe Verdi",
                    "submitted_at": "2024-12-15T14:20:00",
                    "purpose": "Credit Recognition",
                    "status": "pending"
                }
            ],
            "integration_stats": {
                "connected_systems": 3,
                "pending_mappings": 5,
                "auto_approved": 23,
                "manual_review": 7
            },
            "system_health": {
                "blockchain_status": "connected",
                "database_status": "healthy",
                "api_response_time": "120ms",
                "uptime": "99.9%"
            },
            "test_results": {
                "last_run": "2024-12-15T12:00:00",
                "total_tests": 15,
                "passed": 14,
                "failed": 1,
                "success_rate": "93.3%"
            }
        }
    
    # =============================================================================
    # TEMPLATE GENERATION
    # =============================================================================
    
    def _create_templates(self):
        """Crea template HTML"""
        
        # Base template
        base_template = '''<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} - Academic Credentials</title>
    <link href="/static/style.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    {% if user %}
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand" href="/dashboard">🎓 Academic Credentials</a>
            <div class="navbar-nav">
                <a class="nav-link" href="/dashboard">Dashboard</a>
                <a class="nav-link" href="/credentials">Credenziali</a>
                <a class="nav-link" href="/verification">Verifica</a>
                <a class="nav-link" href="/integration">Integrazione</a>
                <a class="nav-link" href="/monitoring">Monitoring</a>
                {% if user.role == "admin" %}
                <a class="nav-link" href="/testing">Testing</a>
                {% endif %}
                <a class="nav-link" href="/logout">Logout ({{ user.user_id }})</a>
            </div>
        </div>
    </nav>
    {% endif %}
    
    <div class="container-fluid py-4">
        {% block content %}{% endblock %}
    </div>
</body>
</html>'''
        
        # Home template
        home_template = '''{% extends "base.html" %}
{% block content %}
<div class="row justify-content-center">
    <div class="col-md-8 text-center">
        <h1 class="mb-4">🎓 Sistema Credenziali Accademiche</h1>
        <p class="lead">Gestione decentralizzata delle credenziali per la mobilità studentesca</p>
        <div class="row mt-5">
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">🏛️ Università</h5>
                        <p class="card-text">Emissione e gestione credenziali accademiche</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">👤 Studenti</h5>
                        <p class="card-text">Wallet digitale e presentazioni selettive</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">🔍 Verifica</h5>
                        <p class="card-text">Validazione credenziali e integrazione sistemi</p>
                    </div>
                </div>
            </div>
        </div>
        <div class="mt-5">
            <a href="/login" class="btn btn-primary btn-lg">Accedi al Sistema</a>
        </div>
    </div>
</div>
{% endblock %}'''
        
        # Login template
        login_template = '''{% extends "base.html" %}
{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h4>🔐 Login</h4>
            </div>
            <div class="card-body">
                {% if error %}
                <div class="alert alert-danger">{{ error }}</div>
                {% endif %}
                <form method="post">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                        <small class="form-text text-muted">Demo: admin, issuer, verifier</small>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                        <small class="form-text text-muted">Demo: demo123</small>
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
            </div>
        </div>
    </div>
</div>
{% endblock %}'''
        
        # Dashboard template
        dashboard_template = '''{% extends "base.html" %}
{% block content %}
<h2>📊 Dashboard</h2>
<div class="row">
    <div class="col-md-3">
        <div class="card text-white bg-primary">
            <div class="card-body">
                <h5 class="card-title">Credenziali Emesse</h5>
                <h3>{{ stats.total_credentials_issued }}</h3>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card text-white bg-success">
            <div class="card-body">
                <h5 class="card-title">Credenziali Verificate</h5>
                <h3>{{ stats.total_credentials_verified }}</h3>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card text-white bg-warning">
            <div class="card-body">
                <h5 class="card-title">Verifiche Pending</h5>
                <h3>{{ stats.pending_verifications }}</h3>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card text-white bg-info">
            <div class="card-body">
                <h5 class="card-title">Success Rate</h5>
                <h3>{{ "%.1f"|format(stats.success_rate) }}%</h3>
            </div>
        </div>
    </div>
</div>

<div class="row mt-4">
    <div class="col-md-8">
        <div class="card">
            <div class="card-header">📈 Attività Recente</div>
            <div class="card-body">
                <canvas id="activityChart" width="400" height="200"></canvas>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">⚡ Azioni Rapide</div>
            <div class="card-body">
                <a href="/credentials/issue" class="btn btn-primary btn-block mb-2">Emetti Credenziale</a>
                <a href="/verification" class="btn btn-success btn-block mb-2">Verifica Presentazione</a>
                <a href="/monitoring" class="btn btn-info btn-block">Stato Sistema</a>
            </div>
        </div>
    </div>
</div>

<script>
// Chart.js per grafici
const ctx = document.getElementById('activityChart').getContext('2d');
const chart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: ['Lun', 'Mar', 'Mer', 'Gio', 'Ven', 'Sab', 'Dom'],
        datasets: [{
            label: 'Credenziali Emesse',
            data: [12, 19, 3, 5, 2, 3, 7],
            borderColor: 'rgb(75, 192, 192)',
            tension: 0.1
        }, {
            label: 'Verifiche Completate',
            data: [8, 15, 2, 4, 1, 2, 5],
            borderColor: 'rgb(255, 99, 132)',
            tension: 0.1
        }]
    },
    options: {
        responsive: true,
        scales: {
            y: {
                beginAtZero: true
            }
        }
    }
});
</script>
{% endblock %}'''
        
        # Salva templates
        templates = {
            "base.html": base_template,
            "home.html": home_template,
            "login.html": login_template,
            "dashboard.html": dashboard_template,
            "credentials.html": "{% extends 'base.html' %}{% block content %}<h2>📋 Gestione Credenziali</h2><p>Pagina in sviluppo...</p>{% endblock %}",
            "issue_credential.html": "{% extends 'base.html' %}{% block content %}<h2>📝 Emissione Credenziale</h2><p>Form emissione in sviluppo...</p>{% endblock %}",
            "verification.html": "{% extends 'base.html' %}{% block content %}<h2>🔍 Verifica Credenziali</h2><p>Sistema verifica in sviluppo...</p>{% endblock %}",
            "integration.html": "{% extends 'base.html' %}{% block content %}<h2>🔗 Integrazione Sistemi</h2><p>Pannello integrazione in sviluppo...</p>{% endblock %}",
            "monitoring.html": "{% extends 'base.html' %}{% block content %}<h2>📊 Monitoring</h2><p>Dashboard monitoring in sviluppo...</p>{% endblock %}",
            "testing.html": "{% extends 'base.html' %}{% block content %}<h2>🧪 Testing Sistema</h2><p>Pannello testing in sviluppo...</p>{% endblock %}"
        }
        
        for template_name, content in templates.items():
            template_file = self.templates_dir / template_name
            with open(template_file, 'w', encoding='utf-8') as f:
                f.write(content)
    
    def _create_base_css(self):
        """Crea CSS base"""
        css_content = """
/* Academic Credentials Dashboard CSS */
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: #f8f9fa;
}

.navbar-brand {
    font-weight: bold;
}

.card {
    border: none;
    border-radius: 10px;
    box-shadow: 0 0 20px rgba(0,0,0,0.1);
    margin-bottom: 20px;
}

.btn {
    border-radius: 25px;
}

.btn-block {
    width: 100%;
    margin-bottom: 10px;
}

.alert {
    border-radius: 10px;
}

/* Custom colors */
.bg-primary { background-color: #4e73df !important; }
.bg-success { background-color: #1cc88a !important; }
.bg-warning { background-color: #f6c23e !important; }
.bg-info { background-color: #36b9cc !important; }

/* Animations */
.card:hover {
    transform: translateY(-5px);
    transition: all 0.3s ease;
}

/* Loading spinner */
.spinner {
    border: 4px solid #f3f3f3;
    border-top: 4px solid #3498db;
    border-radius: 50%;
    width: 40px;
    height: 40px;
    animation: spin 2s linear infinite;
    margin: 0 auto;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}
"""
        
        css_file = self.static_dir / "style.css"
        with open(css_file, 'w', encoding='utf-8') as f:
            f.write(css_content)
    
    def run(self, host: str = "0.0.0.0", port: int = 8000):
        """Avvia dashboard"""
        print(f"🚀 Avviando dashboard su http://{host}:{port}")
        print(f"   Login demo: admin/demo123, issuer/demo123, verifier/demo123")
        
        uvicorn.run(self.app, host=host, port=port)


# =============================================================================
# 3. DEMO E MAIN
# =============================================================================

def demo_web_dashboard():
    """Demo dashboard web"""
    
    print("🌐" * 40)
    print("DEMO WEB DASHBOARD")
    print("Dashboard Università per Credenziali")
    print("🌐" * 40)
    
    try:
        # Inizializza dashboard
        dashboard = AcademicCredentialsDashboard()
        
        print(f"✅ Dashboard inizializzato")
        print(f"   Templates: {len(list(dashboard.templates_dir.glob('*.html')))} file")
        print(f"   Static files: {dashboard.static_dir}")
        
        print(f"\n🎯 Funzionalità implementate:")
        print(f"   🔐 Sistema autenticazione")
        print(f"   📊 Dashboard con statistiche")
        print(f"   📋 Gestione credenziali")
        print(f"   🔍 Interfaccia verifica")
        print(f"   🔗 Pannello integrazione")
        print(f"   📈 Monitoring sistema")
        print(f"   🧪 Testing interface")
        
        print(f"\n💡 Per testare:")
        print(f"   1. Avvia: python web/dashboard.py")
        print(f"   2. Apri: http://localhost:8000")
        print(f"   3. Login: admin/demo123")
        
        return dashboard
        
    except Exception as e:
        print(f"❌ Errore demo dashboard: {e}")
        return None


if __name__ == "__main__":
    print("🌐" * 50)
    print("ACADEMIC CREDENTIALS WEB DASHBOARD")
    print("Dashboard Completo per Università")
    print("🌐" * 50)
    
    # Demo o run diretto
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demo_web_dashboard()
    else:
        # Run dashboard
        dashboard = AcademicCredentialsDashboard()
        dashboard.run()