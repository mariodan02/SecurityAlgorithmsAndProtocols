# =============================================================================
# FASE 5: COMUNICAZIONE SICURA - SECURE SERVER
# File: communication/secure_server.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import json
import asyncio
import datetime
import ssl
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import uuid

# FastAPI imports
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import uvicorn

# Pydantic per validazione
from pydantic import BaseModel, Field

# Import moduli interni
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =============================================================================
# 1. MODELLI DATI API
# =============================================================================

class APIResponse(BaseModel):
    """Risposta API standardizzata"""
    success: bool
    message: str
    data: Optional[Any] = None
    timestamp: str = Field(default_factory=lambda: datetime.datetime.utcnow().isoformat())
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class CredentialSubmissionRequest(BaseModel):
    """Richiesta sottomissione credenziale"""
    credential_data: Dict[str, Any]
    student_signature: Optional[str] = None
    presentation_purpose: str
    recipient_id: str
    expires_hours: int = Field(default=24, ge=1, le=168)


class CredentialValidationRequest(BaseModel):
    """Richiesta validazione credenziale"""
    credential_data: Dict[str, Any]
    validation_level: str = "standard"
    include_merkle_verification: bool = True
    check_revocation: bool = True


class CredentialVerificationRequest(BaseModel):
    """Richiesta verifica credenziale (blockchain)"""
    credential_data: Dict[str, Any]
    blockchain_network: str = "mainnet"


class PresentationRequest(BaseModel):
    """Richiesta presentazione credenziale"""
    presentation_data: Dict[str, Any]
    verification_requirements: Optional[Dict[str, Any]] = None


class UniversityRegistrationRequest(BaseModel):
    """Richiesta registrazione università"""
    university_name: str
    country_code: str
    erasmus_code: Optional[str] = None
    contact_email: str
    public_key_pem: str
    certificate_request: Dict[str, Any]


# =============================================================================
# 2. CONFIGURAZIONE SERVER
# =============================================================================

@dataclass
class ServerConfiguration:
    """Configurazione server sicuro"""
    host: str = "localhost"
    port: int = 8443
    ssl_enabled: bool = True
    ssl_cert_file: str = "./certificates/server/secure_server.pem"
    ssl_key_file: str = "./keys/secure_server_private.pem"
    ssl_ca_file: str = "./certificates/ca/ca_certificate.pem"
    cors_origins: List[str] = field(default_factory=lambda: [
        "https://localhost:8443", 
        "http://localhost:8000"  # Aggiungi l'URL del dashboard
    ])

    # Sicurezza
    require_client_certificates: bool = False
    trusted_hosts: List[str] = field(default_factory=lambda: ["localhost", "0.0.0.0"])
    api_key_required: bool = True
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60
    
    # Logging e monitoring
    enable_request_logging: bool = True
    log_file: str = "./logs/secure_server.log"
    max_request_size: int = 10 * 1024 * 1024  # 10MB
    
    # Configurazione blockchain
    blockchain_rpc_url: str = "https://blockchain-rpc.example.com"
    blockchain_api_key: str = "blockchain-api-key-12345"
    blockchain_network: str = "testnet"


# =============================================================================
# 3. MIDDLEWARE E SECURITY
# =============================================================================

class RateLimiter:
    """Rate limiter semplice"""
    
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.clients: Dict[str, List[float]] = {}
    
    def is_allowed(self, client_ip: str) -> bool:
        """Verifica se il client può fare richieste"""
        now = time.time()
        
        if client_ip not in self.clients:
            self.clients[client_ip] = []
        
        # Rimuove richieste vecchie
        self.clients[client_ip] = [
            req_time for req_time in self.clients[client_ip]
            if now - req_time < self.window_seconds
        ]
        
        # Verifica limite
        if len(self.clients[client_ip]) >= self.max_requests:
            return False
        
        # Aggiunge richiesta corrente
        self.clients[client_ip].append(now)
        return True


class APIKeyManager:
    """Gestione API keys per i 3 utenti specifici"""
    
    def __init__(self):
        self.api_keys: Dict[str, Dict[str, Any]] = {
            "issuer_rennes": {
                "username": "issuer_rennes",
                "role": "issuer",
                "university": "Université de Rennes",
                "permissions": ["submit_credential", "validate_credential"],
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            },
            "verifier_unisa": {
                "username": "verifier_unisa",
                "role": "verifier",
                "university": "Università di Salerno",
                "permissions": ["validate_credential", "submit_presentation"],
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            },
            "studente_mariorossi": {
                "username": "studente_mariorossi",
                "role": "studente",
                "university": "Studente",
                "permissions": ["verify_credential", "submit_presentation"],
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
        }
    
    def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Valida API key"""
        return self.api_keys.get(api_key)
    
    def has_permission(self, api_key: str, permission: str) -> bool:
        """Verifica permessi"""
        key_info = self.validate_api_key(api_key)
        if not key_info:
            return False
        
        permissions = key_info.get("permissions", [])
        return permission in permissions
    
class CredentialRequest(BaseModel):
    student_name: str
    student_id: str
    purpose: str
    requested_at: str


# =============================================================================
# 4. SECURE SERVER PRINCIPALE
# =============================================================================

class AcademicCredentialsSecureServer:
    """Server sicuro per il sistema di credenziali accademiche"""
    
    def __init__(self, config: ServerConfiguration):
        """
        Inizializza il server sicuro
        
        Args:
            config: Configurazione server
        """
        self.config = config
        self.app = FastAPI(
            title="Academic Credentials Secure API",
            description="API sicura per il sistema di credenziali accademiche",
            version="1.0.0",
            docs_url="/docs" if not config.api_key_required else None
        )
        
        # Componenti di sicurezza
        self.rate_limiter = RateLimiter(
            config.rate_limit_requests, 
            config.rate_limit_window_seconds
        )
        self.api_key_manager = APIKeyManager()
        self.security = HTTPBearer() if config.api_key_required else None
        
        # Storage
        self.submitted_credentials: Dict[str, Dict[str, Any]] = {}
        self.validation_requests: Dict[str, Dict[str, Any]] = {}
        
        # Statistiche
        self.stats = {
            'requests_received': 0,
            'credentials_submitted': 0,
            'validations_performed': 0,
            'verifications_performed': 0,
            'authentication_failures': 0,
            'rate_limit_hits': 0
        }
        
        # Setup middleware e routes
        self._setup_middleware()
        self._setup_routes()
        
        print(f"🌐 Secure Server inizializzato")
        print(f"   Host: {config.host}:{config.port}")
        print(f"   SSL: {'Abilitato' if config.ssl_enabled else 'Disabilitato'}")
        print(f"   API Key: {'Richiesta' if config.api_key_required else 'Opzionale'}")
    
    def _setup_middleware(self):
        """Configura middleware di sicurezza"""
        
        # CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=self.config.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["*"],
        )
        
        # Trusted hosts
        self.app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=self.config.trusted_hosts
        )
        
        # Rate limiting middleware
        @self.app.middleware("http")
        async def rate_limit_middleware(request: Request, call_next):
            client_ip = request.client.host
            
            if not self.rate_limiter.is_allowed(client_ip):
                self.stats['rate_limit_hits'] += 1
                return JSONResponse(
                    status_code=429,
                    content={"error": "Rate limit exceeded"}
                )
            
            response = await call_next(request)
            return response
        
        # Request logging
        if self.config.enable_request_logging:
            @self.app.middleware("http")
            async def logging_middleware(request: Request, call_next):
                start_time = time.time()
                
                response = await call_next(request)
                
                process_time = time.time() - start_time
                
                print(f"📊 {request.method} {request.url.path} - "
                      f"{response.status_code} - {process_time:.3f}s")
                
                self.stats['requests_received'] += 1
                return response
    
    def _setup_routes(self):
        """Configura routes API"""
                
        # Submit credential
        @self.app.post("/api/v1/credentials/submit")
        async def submit_credential(
            request: CredentialSubmissionRequest,
            auth: HTTPAuthorizationCredentials = Depends(self.security) if self.security else None
        ):
            return await self._handle_credential_submission(request, auth)
        
        # Validate credential (solo per issuer/verifier)
        @self.app.post("/api/v1/credentials/validate")
        async def validate_credential(
            request: CredentialValidationRequest,
            auth: HTTPAuthorizationCredentials = Depends(self.security) if self.security else None
        ):
            return await self._handle_credential_validation(request, auth)
        
        # Verify credential (tutti gli utenti)
        @self.app.post("/api/v1/credentials/verify")
        async def verify_credential(
            request: CredentialVerificationRequest,
            auth: HTTPAuthorizationCredentials = Depends(self.security) if self.security else None
        ):
            return await self._handle_credential_verification(request, auth)
        
        @self.app.post("/api/v1/credentials/request")
        async def handle_credential_request(
            request: CredentialRequest,
            auth: HTTPAuthorizationCredentials = Depends(self.security) if self.security else None
        ):
            """Endpoint per richiedere credenziali (protetto da TLS)"""
            try:
                auth_info = await self._authenticate_request(auth)
                
                if auth_info["role"] != "issuer":
                    raise HTTPException(status_code=403, detail="Solo issuer possono gestire richieste")
                
                # Simula elaborazione richiesta
                request_id = f"req_{uuid.uuid4().hex[:10]}"
                print(f"📩 Ricevuta richiesta credenziale da {request.student_name} ({request.student_id})")
                print(f"   Scopo: {request.purpose}")
                print(f"   ID Richiesta: {request_id}")
                
                # Simula tempi di elaborazione
                await asyncio.sleep(1)
                
                return APIResponse(
                    success=True,
                    message="Richiesta credenziale ricevuta",
                    data={
                        "request_id": request_id,
                        "status": "in_processing",
                        "estimated_completion": (
                            datetime.datetime.now(datetime.timezone.utc) + 
                            datetime.timedelta(days=3)
                        ).isoformat()
                    }
                )
                
            except HTTPException:
                raise
            except Exception as e:
                return APIResponse(
                    success=False,
                    message=f"Errore interno: {e}"
                )

        # Submit presentation
        @self.app.post("/api/v1/presentations/submit")
        async def submit_presentation(
            request: PresentationRequest,
            auth: HTTPAuthorizationCredentials = Depends(self.security) if self.security else None
        ):
            return await self._handle_presentation_submission(request, auth)
        
        # Get credential status
        @self.app.get("/api/v1/credentials/{credential_id}/status")
        async def get_credential_status(
            credential_id: str,
            auth: HTTPAuthorizationCredentials = Depends(self.security) if self.security else None
        ):
            return await self._handle_credential_status(credential_id, auth)
        
        @self.app.get("/api/v1/universities/certificate")
        async def get_university_certificate(name: str):
            """Restituisce il certificato PEM di un'università"""
            try:
                # Mappa demo delle università 
                university_certs = {
                    "Université de Rennes": "./certificates/issued/university_FR_RENNES01_1001.pem",
                   "Università di Salerno": "./certificates/issued/university_IT_SALERNO_2001.pem"
                }
                
                if name not in university_certs:
                    return JSONResponse(
                        {"success": False, "message": "Università non trovata"},
                        status_code=404
                    )
                
                cert_path = university_certs[name]
                if not Path(cert_path).exists():
                    return JSONResponse(
                        {"success": False, "message": "Certificato non disponibile"},
                        status_code=404
                    )
                
                with open(cert_path, "r") as f:
                    cert_pem = f.read()
                
                return JSONResponse({
                    "success": True,
                    "data": {
                        "university_name": name,
                        "certificate_pem": cert_pem
                    }
                })
                
            except Exception as e:
                return JSONResponse(
                    {"success": False, "message": f"Errore interno: {str(e)}"},
                    status_code=500
                )

        # Statistics endpoint
        @self.app.get("/api/v1/stats")
        async def get_statistics(
            auth: HTTPAuthorizationCredentials = Depends(self.security) if self.security else None
        ):
            # Solo issuer e verifier possono vedere le statistiche
            auth_info = await self._authenticate_request(auth)
            if auth_info["role"] not in ["issuer", "verifier"]:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            
            return APIResponse(
                success=True,
                message="Statistiche server",
                data=self.stats
            )
    
    async def _authenticate_request(self, auth: Optional[HTTPAuthorizationCredentials]) -> Optional[Dict[str, Any]]:
        """Autentica richiesta"""
        if not self.config.api_key_required:
            return {"username": "anonymous", "role": "anonymous", "permissions": []}
        
        if not auth:
            self.stats['authentication_failures'] += 1
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API Key richiesta",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        api_key_info = self.api_key_manager.validate_api_key(auth.credentials)
        if not api_key_info:
            self.stats['authentication_failures'] += 1
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API Key non valida",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return api_key_info
    
    async def _handle_credential_submission(self, 
                                          request: CredentialSubmissionRequest,
                                          auth: Optional[HTTPAuthorizationCredentials]) -> APIResponse:
        """Gestisce sottomissione credenziale"""
        try:
            # Autentica
            auth_info = await self._authenticate_request(auth)
            
            # Solo issuer può sottomettere credenziali
            if auth_info["role"] != "issuer":
                raise HTTPException(status_code=403, detail="Solo issuer può sottomettere credenziali")
            
            print(f"📤 Ricevuta sottomissione credenziale da {auth_info['username']}")
            
            # Genera ID sottomissione
            submission_id = str(uuid.uuid4())
            
            # Salva sottomissione
            self.submitted_credentials[submission_id] = {
                'credential': request.credential_data,
                'submitted_by': auth_info['username'],
                'submission_time': datetime.datetime.utcnow().isoformat(),
                'purpose': request.presentation_purpose,
                'recipient': request.recipient_id,
                'expires_at': (
                    datetime.datetime.utcnow() + 
                    datetime.timedelta(hours=request.expires_hours)
                ).isoformat(),
                'status': 'submitted'
            }
            
            self.stats['credentials_submitted'] += 1
            
            return APIResponse(
                success=True,
                message="Credenziale sottomessa con successo",
                data={
                    "submission_id": submission_id,
                    "status": "submitted"
                }
            )
            
        except HTTPException:
            raise
        except Exception as e:
            print(f"❌ Errore sottomissione credenziale: {e}")
            return APIResponse(
                success=False,
                message=f"Errore interno: {e}"
            )
    
    async def _handle_credential_validation(self,
                                          request: CredentialValidationRequest,
                                          auth: Optional[HTTPAuthorizationCredentials]) -> APIResponse:
        """Gestisce validazione credenziale (solo issuer/verifier)"""
        try:
            # Autentica
            auth_info = await self._authenticate_request(auth)
            
            # Solo issuer e verifier possono validare
            if auth_info["role"] not in ["issuer", "verifier"]:
                raise HTTPException(status_code=403, detail="Non autorizzato a validare credenziali")
            
            print(f"🔍 Ricevuta richiesta validazione da {auth_info['username']}")
            
            # Genera ID validazione
            validation_id = str(uuid.uuid4())
            
            # Simula validazione
            validation_report = {
                "is_valid": True,
                "errors": [],
                "warnings": []
            }
            
            # Salva richiesta validazione
            self.validation_requests[validation_id] = {
                'credential_data': request.credential_data,
                'requested_by': auth_info['username'],
                'request_time': datetime.datetime.utcnow().isoformat(),
                'validation_report': validation_report
            }
            
            self.stats['validations_performed'] += 1
            
            return APIResponse(
                success=True,
                message="Validazione completata",
                data={
                    "validation_id": validation_id,
                    "validation_result": "valid",
                    "is_valid": True
                }
            )
            
        except HTTPException:
            raise
        except Exception as e:
            print(f"❌ Errore validazione credenziale: {e}")
            return APIResponse(
                success=False,
                message=f"Errore interno: {e}"
            )
            
    async def _handle_credential_verification(self,
                                            request: CredentialVerificationRequest,
                                            auth: Optional[HTTPAuthorizationCredentials]) -> APIResponse:
        """Gestisce verifica credenziale (tutti gli utenti)"""
        try:
            # Autentica
            auth_info = await self._authenticate_request(auth)
            
            print(f"🔍 Ricevuta richiesta verifica da {auth_info['username']}")
            
            # Genera ID verifica
            verification_id = str(uuid.uuid4())
            
            # Simula verifica blockchain
            # (In un'implementazione reale, qui si chiamerebbe il modulo blockchain)
            blockchain_result = {
                "on_chain": False,
                "block_number": 123456,
                "transaction_hash": "0x1234567890abcdef",
                "timestamp": "2025-07-18T12:34:56Z",
                "is_valid": False,
                "revoked": False  
            }
            
            self.stats['verifications_performed'] += 1
            
            return APIResponse(
                success=True,
                message="Verifica blockchain completata",
                data={
                    "verification_id": verification_id,
                    "blockchain_result": blockchain_result
                }
            )
            
        except HTTPException:
            raise
        except Exception as e:
            print(f"❌ Errore verifica credenziale: {e}")
            return APIResponse(
                success=False,
                message=f"Errore interno: {e}"
            )
    
    async def _handle_presentation_submission(self,
                                            request: PresentationRequest,
                                            auth: Optional[HTTPAuthorizationCredentials]) -> APIResponse:
        """Gestisce sottomissione presentazione"""
        try:
            auth_info = await self._authenticate_request(auth)
            
            print(f"📋 Ricevuta presentazione da {auth_info['username']}")
            
            # Genera ID ricezione
            reception_id = str(uuid.uuid4())
            
            return APIResponse(
                success=True,
                message="Presentazione ricevuta",
                data={
                    "reception_id": reception_id,
                    "presentation_id": request.presentation_data.get("presentation_id", "unknown"),
                    "status": "received"
                }
            )
            
        except HTTPException:
            raise
        except Exception as e:
            print(f"❌ Errore ricezione presentazione: {e}")
            return APIResponse(
                success=False,
                message=f"Errore interno: {e}"
            )
    
    async def _handle_credential_status(self,
                                      credential_id: str,
                                      auth: Optional[HTTPAuthorizationCredentials]) -> APIResponse:
        """Gestisce richiesta status credenziale"""
        try:
            auth_info = await self._authenticate_request(auth)
            
            print(f"📊 Richiesta status credenziale: {credential_id[:8]}...")
            
            # Cerca nelle sottomissioni
            for submission_id, submission in self.submitted_credentials.items():
                cred_data = submission['credential']
                if cred_data.get('metadata', {}).get('credential_id') == credential_id:
                    return APIResponse(
                        success=True,
                        message="Status credenziale trovato",
                        data={
                            "credential_id": credential_id,
                            "status": submission['status'],
                            "submitted_by": submission['submitted_by'],
                            "submission_time": submission['submission_time'],
                            "expires_at": submission['expires_at']
                        }
                    )
            
            # Non trovata
            return APIResponse(
                success=False,
                message="Credenziale non trovata",
                data={"credential_id": credential_id}
            )
            
        except HTTPException:
            raise
        except Exception as e:
            print(f"❌ Errore status credenziale: {e}")
            return APIResponse(
                success=False,
                message=f"Errore interno: {e}"
            )
    

    def run(self):
        """Avvia il server"""
        try:
            print(f"🚀 Avvio server su {self.config.host}:{self.config.port}")
            
            ssl_context = None
            if self.config.ssl_enabled:
                # Carica i certificati esistenti
                if Path(self.config.ssl_cert_file).exists() and Path(self.config.ssl_key_file).exists():
                    # Usa SSLContext per configurare la password HARDCODED
                    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ssl_context.load_cert_chain(
                        self.config.ssl_cert_file,
                        keyfile=self.config.ssl_key_file,
                        password="Unisa2025"  # PASSWORD HARDCODED - CAMBIA SE NECESSARIO
                    )
                    print(f"✅ SSL configurato con certificati esistenti")
                else:
                    print(f"❌ Certificati SSL non trovati")
                    print(f"   Certificato: {self.config.ssl_cert_file}")
                    print(f"   Chiave: {self.config.ssl_key_file}")
                    print(f"⚠️  Genera prima i certificati con certificate_authority.py")
                    return
                    
            # Configura i parametri per uvicorn
            uvicorn_config = {
                "app": self.app,
                "host": self.config.host,
                "port": self.config.port,
                "log_level": "warning",  # Logging ridotto
                "access_log": False      # Disabilita access log
            }
            
            # Configurazione SSL
            if self.config.ssl_enabled and ssl_context:
                uvicorn_config["ssl_certfile"] = self.config.ssl_cert_file
                uvicorn_config["ssl_keyfile"] = self.config.ssl_key_file
                uvicorn_config["ssl_keyfile_password"] = "Unisa2025"  
            
            # Avvia server
            uvicorn.run(**uvicorn_config)
            
        except Exception as e:
            print(f"❌ Errore avvio server: {e}")
            raise