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

try:
    from crypto.foundations import CryptoUtils, DigitalSignature
    from credentials.models import AcademicCredential
    from credentials.validator import AcademicCredentialValidator, ValidationLevel
    from pki.certificate_manager import CertificateManager
except ImportError as e:
    print(f"⚠️  Errore import moduli interni: {e}")
    print("   Assicurati che tutti i moduli siano presenti nel progetto")
    raise


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
    ssl_cert_file: str = "./certificates/server/server.crt"
    ssl_key_file: str = "./certificates/server/server.key"
    ssl_ca_file: str = "./certificates/ca/ca_certificate.pem"
    
    # Sicurezza
    require_client_certificates: bool = False
    trusted_hosts: List[str] = field(default_factory=lambda: ["localhost", "127.0.0.1"])
    cors_origins: List[str] = field(default_factory=lambda: ["https://localhost:*"])
    api_key_required: bool = True
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60
    
    # Logging e monitoring
    enable_request_logging: bool = True
    log_file: str = "./logs/secure_server.log"
    max_request_size: int = 10 * 1024 * 1024  # 10MB


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
    """Gestione API keys"""
    
    def __init__(self):
        self.api_keys: Dict[str, Dict[str, Any]] = {}
        self._load_api_keys()
    
    def _load_api_keys(self):
        """Carica API keys da file o genera default"""
        # Keys predefinite per demo
        self.api_keys = {
            "unisa_key_123": {
                "university": "Università di Salerno",
                "permissions": ["submit_credential", "validate_credential"],
                "created_at": datetime.datetime.utcnow().isoformat()
            },
            "rennes_key_456": {
                "university": "Université de Rennes", 
                "permissions": ["submit_credential", "validate_credential"],
                "created_at": datetime.datetime.utcnow().isoformat()
            },
            "admin_key_789": {
                "university": "System Administrator",
                "permissions": ["*"],
                "created_at": datetime.datetime.utcnow().isoformat()
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
        return "*" in permissions or permission in permissions


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
        
        # Componenti del sistema
        self.crypto_utils = CryptoUtils()
        self.credential_validator = AcademicCredentialValidator()
        self.cert_manager = CertificateManager()
        
        # Storage
        self.submitted_credentials: Dict[str, Dict[str, Any]] = {}
        self.validation_requests: Dict[str, Dict[str, Any]] = {}
        
        # Statistiche
        self.stats = {
            'requests_received': 0,
            'credentials_submitted': 0,
            'validations_performed': 0,
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
        
        # Health check
        @self.app.get("/health")
        async def health_check():
            return APIResponse(
                success=True,
                message="Server operativo",
                data={
                    "status": "healthy",
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "stats": self.stats
                }
            )
        
        # Submit credential
        @self.app.post("/api/v1/credentials/submit")
        async def submit_credential(
            request: CredentialSubmissionRequest,
            auth: HTTPAuthorizationCredentials = Depends(self.security) if self.security else None
        ):
            return await self._handle_credential_submission(request, auth)
        
        # Validate credential
        @self.app.post("/api/v1/credentials/validate")
        async def validate_credential(
            request: CredentialValidationRequest,
            auth: HTTPAuthorizationCredentials = Depends(self.security) if self.security else None
        ):
            return await self._handle_credential_validation(request, auth)
        
        # Submit presentation
        @self.app.post("/api/v1/presentations/submit")
        async def submit_presentation(
            request: PresentationRequest,
            auth: HTTPAuthorizationCredentials = Depends(self.security) if self.security else None
        ):
            return await self._handle_presentation_submission(request, auth)
        
        # University registration
        @self.app.post("/api/v1/universities/register")
        async def register_university(
            request: UniversityRegistrationRequest,
            auth: HTTPAuthorizationCredentials = Depends(self.security) if self.security else None
        ):
            return await self._handle_university_registration(request, auth)
        
        # Get credential status
        @self.app.get("/api/v1/credentials/{credential_id}/status")
        async def get_credential_status(
            credential_id: str,
            auth: HTTPAuthorizationCredentials = Depends(self.security) if self.security else None
        ):
            return await self._handle_credential_status(credential_id, auth)
        
        # Statistics endpoint
        @self.app.get("/api/v1/stats")
        async def get_statistics(
            auth: HTTPAuthorizationCredentials = Depends(self.security) if self.security else None
        ):
            if auth and not self.api_key_manager.has_permission(auth.credentials, "admin"):
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            
            return APIResponse(
                success=True,
                message="Statistiche server",
                data=self.stats
            )
    
    async def _authenticate_request(self, auth: Optional[HTTPAuthorizationCredentials]) -> Optional[Dict[str, Any]]:
        """Autentica richiesta"""
        if not self.config.api_key_required:
            return {"university": "anonymous", "permissions": ["*"]}
        
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
            
            # Verifica permessi
            if not self.api_key_manager.has_permission(auth.credentials if auth else "anonymous", "submit_credential"):
                raise HTTPException(status_code=403, detail="Permessi insufficienti")
            
            print(f"📤 Ricevuta sottomissione credenziale da {auth_info['university']}")
            
            # Valida credenziale
            try:
                credential = AcademicCredential.from_dict(request.credential_data)
            except Exception as e:
                return APIResponse(
                    success=False,
                    message=f"Formato credenziale non valido: {e}"
                )
            
            # Validazione base
            validation_report = self.credential_validator.validate_credential(
                credential, ValidationLevel.STANDARD
            )
            
            if not validation_report.is_valid():
                return APIResponse(
                    success=False,
                    message="Credenziale non valida",
                    data={
                        "validation_errors": [e.message for e in validation_report.errors],
                        "validation_warnings": [w.message for w in validation_report.warnings]
                    }
                )
            
            # Genera ID sottomissione
            submission_id = str(uuid.uuid4())
            
            # Salva sottomissione
            self.submitted_credentials[submission_id] = {
                'credential': request.credential_data,
                'submitted_by': auth_info['university'],
                'submission_time': datetime.datetime.utcnow().isoformat(),
                'purpose': request.presentation_purpose,
                'recipient': request.recipient_id,
                'expires_at': (
                    datetime.datetime.utcnow() + 
                    datetime.timedelta(hours=request.expires_hours)
                ).isoformat(),
                'status': 'submitted',
                'validation_report': validation_report.to_dict()
            }
            
            self.stats['credentials_submitted'] += 1
            
            return APIResponse(
                success=True,
                message="Credenziale sottomessa con successo",
                data={
                    "submission_id": submission_id,
                    "status": "submitted",
                    "validation_summary": {
                        "format_valid": validation_report.format_valid,
                        "signature_valid": validation_report.signature_valid,
                        "merkle_tree_valid": validation_report.merkle_tree_valid
                    }
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
        """Gestisce validazione credenziale"""
        try:
            # Autentica
            auth_info = await self._authenticate_request(auth)
            
            print(f"🔍 Ricevuta richiesta validazione da {auth_info['university']}")
            
            # Parse livello validazione
            validation_level_map = {
                "basic": ValidationLevel.BASIC,
                "standard": ValidationLevel.STANDARD,
                "complete": ValidationLevel.COMPLETE,
                "forensic": ValidationLevel.FORENSIC
            }
            
            validation_level = validation_level_map.get(
                request.validation_level.lower(), ValidationLevel.STANDARD
            )
            
            # Valida credenziale
            try:
                credential = AcademicCredential.from_dict(request.credential_data)
            except Exception as e:
                return APIResponse(
                    success=False,
                    message=f"Formato credenziale non valido: {e}"
                )
            
            # Esegue validazione
            validation_report = self.credential_validator.validate_credential(
                credential, validation_level
            )
            
            # Genera ID validazione
            validation_id = str(uuid.uuid4())
            
            # Salva richiesta validazione
            self.validation_requests[validation_id] = {
                'credential_id': str(credential.metadata.credential_id),
                'requested_by': auth_info['university'],
                'request_time': datetime.datetime.utcnow().isoformat(),
                'validation_level': validation_level.value,
                'validation_report': validation_report.to_dict()
            }
            
            self.stats['validations_performed'] += 1
            
            return APIResponse(
                success=True,
                message="Validazione completata",
                data={
                    "validation_id": validation_id,
                    "validation_result": validation_report.overall_result.value,
                    "is_valid": validation_report.is_valid(),
                    "validation_details": {
                        "format_valid": validation_report.format_valid,
                        "signature_valid": validation_report.signature_valid,
                        "certificate_valid": validation_report.certificate_valid,
                        "merkle_tree_valid": validation_report.merkle_tree_valid,
                        "temporal_valid": validation_report.temporal_valid,
                        "revocation_status": validation_report.revocation_status
                    },
                    "errors": [e.to_dict() for e in validation_report.errors],
                    "warnings": [w.to_dict() for w in validation_report.warnings],
                    "validation_duration_ms": validation_report.validation_duration_ms
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
    
    async def _handle_presentation_submission(self,
                                            request: PresentationRequest,
                                            auth: Optional[HTTPAuthorizationCredentials]) -> APIResponse:
        """Gestisce sottomissione presentazione"""
        try:
            auth_info = await self._authenticate_request(auth)
            
            print(f"📋 Ricevuta presentazione da {auth_info['university']}")
            
            # Valida formato presentazione
            required_fields = ['presentation_id', 'selective_disclosures']
            for field in required_fields:
                if field not in request.presentation_data:
                    return APIResponse(
                        success=False,
                        message=f"Campo obbligatorio mancante: {field}"
                    )
            
            # Genera ID ricezione
            reception_id = str(uuid.uuid4())
            
            # TODO: Implementare validazione completa presentazione
            # Per ora accetta la presentazione
            
            return APIResponse(
                success=True,
                message="Presentazione ricevuta",
                data={
                    "reception_id": reception_id,
                    "presentation_id": request.presentation_data["presentation_id"],
                    "status": "received",
                    "disclosures_count": len(request.presentation_data.get("selective_disclosures", []))
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
    
    async def _handle_university_registration(self,
                                            request: UniversityRegistrationRequest,
                                            auth: Optional[HTTPAuthorizationCredentials]) -> APIResponse:
        """Gestisce registrazione università"""
        try:
            auth_info = await self._authenticate_request(auth)
            
            # Solo admin può registrare nuove università
            if not self.api_key_manager.has_permission(auth.credentials if auth else "anonymous", "admin"):
                raise HTTPException(status_code=403, detail="Solo amministratori possono registrare università")
            
            print(f"🏛️  Richiesta registrazione università: {request.university_name}")
            
            # Genera ID registrazione
            registration_id = str(uuid.uuid4())
            
            # TODO: Implementare processo completo registrazione
            # Per ora simula accettazione
            
            return APIResponse(
                success=True,
                message="Richiesta registrazione ricevuta",
                data={
                    "registration_id": registration_id,
                    "university_name": request.university_name,
                    "status": "pending_verification"
                }
            )
            
        except HTTPException:
            raise
        except Exception as e:
            print(f"❌ Errore registrazione università: {e}")
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
            
            # Configurazione SSL
            ssl_context = None
            if self.config.ssl_enabled:
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                
                if Path(self.config.ssl_cert_file).exists() and Path(self.config.ssl_key_file).exists():
                    ssl_context.load_cert_chain(
                        self.config.ssl_cert_file,
                        self.config.ssl_key_file
                    )
                    print(f"✅ SSL configurato con certificati")
                else:
                    print(f"⚠️  Certificati SSL non trovati, genero self-signed...")
                    ssl_context = self._generate_self_signed_ssl()
            
            # Avvia server
            uvicorn.run(
                self.app,
                host=self.config.host,
                port=self.config.port,
                ssl_keyfile=self.config.ssl_key_file if self.config.ssl_enabled else None,
                ssl_certfile=self.config.ssl_cert_file if self.config.ssl_enabled else None,
                log_level="info"
            )
            
        except Exception as e:
            print(f"❌ Errore avvio server: {e}")
            raise
    
    def _generate_self_signed_ssl(self) -> ssl.SSLContext:
        """Genera certificati SSL self-signed per demo"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            import ipaddress
            
            # Genera chiave privata
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Crea certificato self-signed
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Campania"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Salerno"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Academic Credentials Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Salva certificato e chiave
            cert_dir = Path(self.config.ssl_cert_file).parent
            cert_dir.mkdir(parents=True, exist_ok=True)
            
            # Salva certificato
            with open(self.config.ssl_cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            # Salva chiave privata
            with open(self.config.ssl_key_file, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            print(f"✅ Certificati SSL self-signed generati")
            
            # Crea contesto SSL
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(self.config.ssl_cert_file, self.config.ssl_key_file)
            
            return ssl_context
            
        except Exception as e:
            print(f"❌ Errore generazione SSL: {e}")
            # Fallback: SSL disabilitato
            self.config.ssl_enabled = False
            return None


# =============================================================================
# 3. DEMO E TESTING
# =============================================================================

def demo_secure_server():
    """Demo del Secure Server"""
    
    print("🌐" * 40)
    print("DEMO SECURE SERVER")
    print("Server HTTPS per Credenziali Accademiche")
    print("🌐" * 40)
    
    try:
        # 1. Configurazione server
        print("\n1️⃣ CONFIGURAZIONE SERVER")
        
        config = ServerConfiguration(
            host="localhost",
            port=8443,
            ssl_enabled=True,
            require_client_certificates=False,
            api_key_required=True,
            rate_limit_requests=50,
            enable_request_logging=True
        )
        
        print(f"✅ Server configurato:")
        print(f"   Host: {config.host}:{config.port}")
        print(f"   SSL: {'Abilitato' if config.ssl_enabled else 'Disabilitato'}")
        print(f"   API Key: {'Richiesta' if config.api_key_required else 'Opzionale'}")
        print(f"   Rate Limit: {config.rate_limit_requests} req/min")
        
        # 2. Inizializzazione server
        print("\n2️⃣ INIZIALIZZAZIONE SERVER")
        
        server = AcademicCredentialsSecureServer(config)
        
        print(f"✅ Server inizializzato")
        print(f"   Endpoints configurati: 6")
        print(f"   Middleware attivi: CORS, Rate Limiting, Logging")
        
        # 3. Informazioni API Keys
        print("\n3️⃣ API KEYS DISPONIBILI")
        
        api_keys = {
            "unisa_key_123": "Università di Salerno",
            "rennes_key_456": "Université de Rennes",
            "admin_key_789": "System Administrator"
        }
        
        for key, desc in api_keys.items():
            print(f"   🔑 {key}: {desc}")
        
        # 4. Endpoints disponibili
        print("\n4️⃣ ENDPOINTS DISPONIBILI")
        
        endpoints = [
            ("GET", "/health", "Health check del server"),
            ("POST", "/api/v1/credentials/submit", "Sottomissione credenziale"),
            ("POST", "/api/v1/credentials/validate", "Validazione credenziale"),
            ("POST", "/api/v1/presentations/submit", "Sottomissione presentazione"),
            ("POST", "/api/v1/universities/register", "Registrazione università"),
            ("GET", "/api/v1/credentials/{id}/status", "Status credenziale"),
            ("GET", "/api/v1/stats", "Statistiche server (admin)")
        ]
        
        for method, path, desc in endpoints:
            print(f"   📡 {method:4} {path:35} - {desc}")
        
        # 5. Esempio richieste
        print("\n5️⃣ ESEMPI RICHIESTE")
        
        print("📤 Sottomissione credenziale:")
        print("""
curl -X POST https://localhost:8443/api/v1/credentials/submit \\
  -H "Authorization: Bearer unisa_key_123" \\
  -H "Content-Type: application/json" \\
  -d '{
    "credential_data": {...},
    "presentation_purpose": "Riconoscimento crediti",
    "recipient_id": "università_destinataria",
    "expires_hours": 48
  }'
""")
        
        print("🔍 Validazione credenziale:")
        print("""
curl -X POST https://localhost:8443/api/v1/credentials/validate \\
  -H "Authorization: Bearer rennes_key_456" \\
  -H "Content-Type: application/json" \\
  -d '{
    "credential_data": {...},
    "validation_level": "standard",
    "check_revocation": true
  }'
""")
        
        # 6. Caratteristiche di sicurezza
        print("\n6️⃣ CARATTERISTICHE DI SICUREZZA")
        
        security_features = [
            "🔒 TLS/SSL encryption",
            "🔑 API Key authentication",
            "🛡️  Rate limiting",
            "🌐 CORS protection",
            "🔍 Request logging",
            "✅ Input validation",
            "📊 Security monitoring",
            "🚫 Trusted hosts only"
        ]
        
        for feature in security_features:
            print(f"   {feature}")
        
        # 7. Avvio server (simulato)
        print("\n7️⃣ PRONTO PER AVVIO")
        
        print("🚀 Per avviare il server:")
        print("   python communication/secure_server.py")
        print("")
        print("📚 Documentazione API disponibile su:")
        print("   https://localhost:8443/docs")
        print("")
        print("💡 Usa le API keys fornite per autenticazione")
        
        print("\n" + "✅" * 40)
        print("DEMO SECURE SERVER COMPLETATA!")
        print("✅" * 40)
        
        return server
        
    except Exception as e:
        print(f"\n❌ Errore durante demo: {e}")
        import traceback
        traceback.print_exc()
        return None


# =============================================================================
# 4. MAIN - PUNTO DI INGRESSO
# =============================================================================

if __name__ == "__main__":
    print("🌐" * 50)
    print("SECURE SERVER")
    print("Server HTTPS per Credenziali Accademiche")
    print("🌐" * 50)
    
    # Esegui demo
    server_instance = demo_secure_server()
    
    if server_instance:
        print("\n🎉 Secure Server pronto!")
        print("\nFunzionalità disponibili:")
        print("✅ Server HTTPS con TLS")
        print("✅ API REST sicure")
        print("✅ Autenticazione API Key")
        print("✅ Rate limiting")
        print("✅ Validazione credenziali")
        print("✅ Gestione presentazioni")
        print("✅ Monitoring e logging")
        print("✅ Middleware di sicurezza")
        
        print(f"\n🚀 Avvio server...")
        try:
            server_instance.run()
        except KeyboardInterrupt:
            print("\n🛑 Server fermato dall'utente")
        except Exception as e:
            print(f"\n❌ Errore server: {e}")
    else:
        print("\n❌ Errore inizializzazione Secure Server")