# =============================================================================
# FASTAPI ROUTES PER GESTIONE BLOCKCHAIN CREDENZIALI
# File: src/web/credential_blockchain_api.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security
security = HTTPBearer()

# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class VerifyCredentialRequest(BaseModel):
    credential_id: str = Field(..., description="ID della credenziale da verificare")

class VerifyCredentialResponse(BaseModel):
    success: bool
    credential_id: str
    blockchain_status: Dict[str, Any]
    verified_at: str

class RevokeCredentialRequest(BaseModel):
    credential_id: str = Field(..., description="ID della credenziale da revocare")
    reason: str = Field(..., description="Motivo della revoca")

class RevokeCredentialResponse(BaseModel):
    success: bool
    message: str
    credential_id: str
    reason: str
    revoked_at: str
    blockchain_status: Optional[Dict[str, Any]] = None
    transaction_hash: Optional[str] = None

class BlockchainStatusResponse(BaseModel):
    success: bool
    credential_id: str
    blockchain_status: Dict[str, Any]
    verified_at: str

class HealthCheckResponse(BaseModel):
    healthy: bool
    account_address: Optional[str] = None
    balance_eth: Optional[float] = None
    blockchain_connected: Optional[bool] = None
    checked_at: str
    message: Optional[str] = None

# =============================================================================
# DEPENDENCY INJECTION
# =============================================================================

def get_blockchain_service():
    """Dependency per ottenere il servizio blockchain"""
    try:
        from src.blockchain.blockchain_service import BlockchainService
        return BlockchainService()
    except Exception as e:
        logger.error(f"Errore inizializzazione blockchain service: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servizio blockchain non disponibile"
        )

def verify_auth_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Verifica il token di autenticazione.
    Per ora implementazione semplice - adatta in base al tuo sistema di auth.
    """
    # Implementazione base - sostituisci con la tua logica
    if not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token di autenticazione richiesto"
        )
    
    # Qui dovresti verificare il token JWT o session
    # Per ora simulo una verifica semplice
    valid_tokens = {
        "issuer_token": {"username": "issuer_rennes", "role": "issuer"},
        "verifier_token": {"username": "verifier_unisa", "role": "verifier"},
        "student_token": {"username": "studente_mariorossi", "role": "student"}
    }
    
    user_info = valid_tokens.get(credentials.credentials)
    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token non valido"
        )
    
    return user_info

def verify_issuer_role(user_info: dict = Depends(verify_auth_token)):
    """Verifica che l'utente sia un issuer"""
    if user_info.get("role") != "issuer":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Solo gli emittenti possono eseguire questa operazione"
        )
    return user_info

# =============================================================================
# FASTAPI ROUTES
# =============================================================================

def create_credential_blockchain_api() -> FastAPI:
    """Crea l'app FastAPI per la gestione blockchain delle credenziali"""
    
    app = FastAPI(
        title="Academic Credentials Blockchain API",
        description="API per la gestione blockchain delle credenziali accademiche",
        version="1.0.0"
    )

    @app.post("/credentials/verify", response_model=VerifyCredentialResponse)
    async def verify_credential(
        request: VerifyCredentialRequest,
        blockchain_service = Depends(get_blockchain_service),
        user_info: dict = Depends(verify_auth_token)
    ):
        """Verifica lo stato di una credenziale sulla blockchain"""
        try:
            logger.info(f"Verifica credenziale {request.credential_id} richiesta da {user_info['username']}")
            
            # Verifica sulla blockchain
            blockchain_status = blockchain_service.verify_credential(request.credential_id)
            
            return VerifyCredentialResponse(
                success=True,
                credential_id=request.credential_id,
                blockchain_status=blockchain_status,
                verified_at=datetime.now().isoformat()
            )
            
        except Exception as e:
            logger.error(f"Errore durante la verifica della credenziale: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Errore durante la verifica: {str(e)}"
            )

    @app.post("/credentials/revoke", response_model=RevokeCredentialResponse)
    async def revoke_credential(
        request: RevokeCredentialRequest,
        blockchain_service = Depends(get_blockchain_service),
        user_info: dict = Depends(verify_issuer_role)
    ):
        """Revoca una credenziale sulla blockchain"""
        try:
            logger.info(f"Revoca credenziale {request.credential_id} richiesta da {user_info['username']}")
            
            # Prima verifica se la credenziale esiste e non è già revocata
            current_status = blockchain_service.verify_credential(request.credential_id)
            
            if current_status['status'] == 'NOT_FOUND':
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Credenziale non trovata sulla blockchain"
                )
            
            if current_status['status'] == 'REVOKED':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="La credenziale è già stata revocata"
                )

            # Effettua la revoca
            success = blockchain_service.revoke_credential_directly(
                request.credential_id, 
                request.reason
            )

            if not success:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Errore durante la revoca sulla blockchain"
                )

            # Log dell'operazione
            revoke_log = {
                'credential_id': request.credential_id,
                'reason': request.reason,
                'revoked_by': user_info['username'],
                'revoked_at': datetime.now().isoformat(),
                'issuer_address': blockchain_service.account.address
            }
            
            logger.info(f"Credenziale {request.credential_id} revocata con successo: {revoke_log}")

            # Verifica la revoca
            updated_status = blockchain_service.verify_credential(request.credential_id)
            
            return RevokeCredentialResponse(
                success=True,
                message="Credenziale revocata con successo",
                credential_id=request.credential_id,
                reason=request.reason,
                revoked_at=revoke_log['revoked_at'],
                blockchain_status=updated_status,
                transaction_hash="Vedere log console per hash transazione"
            )
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Errore durante la revoca della credenziale: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Errore durante la revoca: {str(e)}"
            )

    @app.get("/credentials/blockchain-status/{credential_id}", response_model=BlockchainStatusResponse)
    async def get_credential_blockchain_status(
        credential_id: str,
        blockchain_service = Depends(get_blockchain_service),
        user_info: dict = Depends(verify_auth_token)
    ):
        """Ottiene lo stato di una credenziale sulla blockchain (endpoint GET)"""
        try:
            blockchain_status = blockchain_service.verify_credential(credential_id)
            
            return BlockchainStatusResponse(
                success=True,
                credential_id=credential_id,
                blockchain_status=blockchain_status,
                verified_at=datetime.now().isoformat()
            )
            
        except Exception as e:
            logger.error(f"Errore durante il recupero dello stato: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Errore: {str(e)}"
            )

    @app.get("/api/blockchain/health", response_model=HealthCheckResponse)
    async def blockchain_health_check():
        """Endpoint per verificare lo stato del servizio blockchain"""
        try:
            blockchain_service = get_blockchain_service()
            
            # Test connessione
            account_address = blockchain_service.account.address
            balance = blockchain_service.w3.eth.get_balance(account_address)
            balance_eth = blockchain_service.w3.from_wei(balance, 'ether')

            return HealthCheckResponse(
                healthy=True,
                account_address=account_address,
                balance_eth=float(balance_eth),
                blockchain_connected=blockchain_service.w3.is_connected(),
                checked_at=datetime.now().isoformat()
            )

        except Exception as e:
            return HealthCheckResponse(
                healthy=False,
                checked_at=datetime.now().isoformat(),
                message=f"Errore health check: {str(e)}"
            )

    # Route per documentazione automatica
    @app.get("/")
    async def root():
        return {
            "message": "Academic Credentials Blockchain API",
            "version": "1.0.0",
            "docs": "/docs",
            "redoc": "/redoc"
        }

    return app

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def format_blockchain_status(status_result: Dict[str, Any]) -> Dict[str, str]:
    """Formatta il risultato dello stato blockchain per la visualizzazione"""
    if status_result['status'] == 'VALID':
        return {
            'status': 'Attiva',
            'status_class': 'success',
            'icon': '✅',
            'details': f"Emessa da {status_result['issuer']}"
        }
    elif status_result['status'] == 'REVOKED':
        return {
            'status': 'Revocata',
            'status_class': 'danger',
            'icon': '🚫',
            'details': 'Credenziale revocata'
        }
    elif status_result['status'] == 'NOT_FOUND':
        return {
            'status': 'Non trovata',
            'status_class': 'warning',
            'icon': '⚠️',
            'details': 'Non registrata su blockchain'
        }
    else:
        return {
            'status': 'Sconosciuto',
            'status_class': 'secondary',
            'icon': '❓',
            'details': 'Stato non determinabile'
        }

def log_credential_action(action: str, credential_id: str, user: str, details: Optional[Dict] = None):
    """Registra le azioni sulle credenziali per audit"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'action': action,
        'credential_id': credential_id,
        'user': user,
        'details': details
    }
    
    logger.info(f"Credential Action: {json.dumps(log_entry)}")
    return log_entry

# =============================================================================
# SCRIPT DI TEST
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    print("🧪 Test API Blockchain Credenziali")
    app = create_credential_blockchain_api()
    
    print("🚀 Avvio server di test...")
    print("📖 Documentazione API: http://localhost:8001/docs")
    print("🔍 ReDoc: http://localhost:8001/redoc")
    
    uvicorn.run(app, host="0.0.0.0", port=8001, reload=True)