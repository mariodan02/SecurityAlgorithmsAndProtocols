# run_wallet_listener.py - Versione con supporto HTTPS

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import json
import os
from datetime import datetime
import uvicorn
import socket
import ssl
from pathlib import Path

# --- CONFIGURAZIONE ---
WALLET_ID = "studente_mariorossi_wallet"
USE_HTTPS = True  # Cambia a False per usare solo HTTP
PORT = 8080
# --------------------

def get_local_ip():
    """Ottiene l'IP locale della macchina"""
    try:
        # Connessione temporanea per ottenere l'IP locale
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def check_ssl_certificates():
    """Verifica se esistono i certificati SSL necessari"""
    cert_paths = [
        "./certificates/wallet/wallet_cert.pem",
        "./certificates/server/secure_server.pem",  # Riusa certificati esistenti
        "./certificates/ca/ca_certificate.pem"
    ]
    
    key_paths = [
        "./keys/wallet_private.pem", 
        "./keys/secure_server_private.pem",  # Riusa chiavi esistenti
        "./keys/ca_private.pem"
    ]
    
    for cert_path in cert_paths:
        for key_path in key_paths:
            if Path(cert_path).exists() and Path(key_path).exists():
                return cert_path, key_path
    
    return None, None

def create_ssl_context():
    """Crea il contesto SSL per HTTPS"""
    cert_path, key_path = check_ssl_certificates()
    
    if not cert_path or not key_path:
        print("❌ ERRORE: Certificati SSL non trovati!")
        print("💡 Certificati necessari:")
        print("   - ./certificates/wallet/wallet_cert.pem")
        print("   - ./keys/wallet_private.pem")
        print("💡 Oppure riusa quelli esistenti:")
        print("   - ./certificates/server/secure_server.pem") 
        print("   - ./keys/secure_server_private.pem")
        return None
    
    try:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_path, keyfile=key_path, password="Unisa2025")
        print(f"🔒 SSL configurato con:")
        print(f"   Certificato: {cert_path}")
        print(f"   Chiave: {key_path}")
        return cert_path, key_path
    except Exception as e:
        print(f"❌ Errore configurazione SSL: {e}")
        return None

# Preparazione dell'ambiente
WALLET_DIR = os.path.join('src', 'credentials', WALLET_ID)
os.makedirs(WALLET_DIR, exist_ok=True)

app = FastAPI(
    title="Student Wallet Listener (HTTPS)",
    description="Riceve credenziali accademiche dall'università via HTTPS sicuro",
    version="2.0.0"
)

# Abilita CORS per HTTPS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "*",  # Per development - in produzione limitare
        "https://localhost:8443",
        "https://127.0.0.1:8443",
        "http://localhost:8000"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Statistiche
stats = {
    "credentials_received": 0,
    "start_time": datetime.now(),
    "last_received": None
}

def print_banner():
    """Stampa il banner di avvio con informazioni utili"""
    local_ip = get_local_ip()
    protocol = "https" if USE_HTTPS else "http"
    
    print("=" * 80)
    print("🎓 STUDENT WALLET LISTENER - RICEVITORE CREDENZIALI ACCADEMICHE")
    if USE_HTTPS:
        print("🔒 MODALITÀ SICURA HTTPS ATTIVATA")
    print("=" * 80)
    print(f"✅ Wallet ID: {WALLET_ID}")
    print(f"📁 Directory: {os.path.abspath(WALLET_DIR)}")
    print(f"🌐 Server avviato su:")
    print(f"   • Locale:        {protocol}://localhost:{PORT}/api/credential-receiver")
    print(f"   • IP della LAN:  {protocol}://{local_ip}:{PORT}/api/credential-receiver")
    print(f"🔍 Endpoint di test: {protocol}://{local_ip}:{PORT}/")
    print("=" * 80)
    print("📞 ISTRUZIONI PER L'UNIVERSITÀ:")
    print(f"   Inserire nel campo 'Callback URL': {protocol}://{local_ip}:{PORT}/api/credential-receiver")
    if USE_HTTPS:
        print("   ✅ Comunicazione sicura TLS abilitata")
    print("=" * 80)
    print("⏳ In attesa di credenziali...")
    print()

@app.get("/")
async def root():
    """Homepage con informazioni sul servizio"""
    local_ip = get_local_ip()
    uptime = datetime.now() - stats["start_time"]
    protocol = "https" if USE_HTTPS else "http"
    
    return {
        "status": "🟢 ATTIVO",
        "wallet_id": WALLET_ID,
        "service": "Student Wallet Listener",
        "version": "2.0.0 (HTTPS)",
        "protocol": protocol.upper(),
        "secure": USE_HTTPS,
        "uptime_seconds": int(uptime.total_seconds()),
        "uptime_human": str(uptime).split('.')[0],
        "credentials_received": stats["credentials_received"],
        "last_received": stats["last_received"].isoformat() if stats["last_received"] else None,
        "endpoint": f"{protocol}://{local_ip}:{PORT}/api/credential-receiver",
        "instructions": {
            "for_university": f"Inserire questo URL nel dashboard: {protocol}://{local_ip}:{PORT}/api/credential-receiver",
            "test_connection": f"GET {protocol}://{local_ip}:{PORT}/",
            "receive_credential": f"POST {protocol}://{local_ip}:{PORT}/api/credential-receiver"
        }
    }

@app.get("/status")
async def status():
    """Endpoint di stato semplice"""
    return {
        "status": "ok", 
        "service": "wallet-listener", 
        "ready": True,
        "protocol": "HTTPS" if USE_HTTPS else "HTTP",
        "secure": USE_HTTPS
    }

@app.post('/api/credential-receiver')
async def receive_credential(request: Request):
    """Endpoint principale per ricevere credenziali via HTTPS sicuro"""
    
    timestamp = datetime.now()
    protocol = "HTTPS" if USE_HTTPS else "HTTP"
    
    print(f"\n{'='*60}")
    print(f"📥 [{timestamp.strftime('%H:%M:%S')}] CREDENZIALE RICEVUTA VIA {protocol}!")
    print(f"{'='*60}")
    
    try:
        # Ottieni informazioni sulla richiesta
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "Sconosciuto")
        content_type = request.headers.get("content-type", "Sconosciuto")
        
        print(f"🌐 IP Mittente: {client_ip}")
        print(f"🖥️  User Agent: {user_agent}")
        print(f"📋 Content-Type: {content_type}")
        print(f"🔒 Protocollo: {protocol}")
        
        # Verifica che sia una richiesta HTTPS se configurato
        if USE_HTTPS:
            # Controlla headers per confermare HTTPS
            forwarded_proto = request.headers.get("x-forwarded-proto")
            if forwarded_proto:
                print(f"🔗 X-Forwarded-Proto: {forwarded_proto}")
        
        # Recupera i dati JSON dalla richiesta
        try:
            credential_data = await request.json()
        except Exception as json_error:
            print(f"❌ ERRORE: Impossibile parsare il JSON: {json_error}")
            raise HTTPException(status_code=400, detail=f"JSON non valido: {json_error}")
        
        print(f"📄 Dimensione dati ricevuti: {len(str(credential_data))} caratteri")
        
        # Verifica che ci siano dati
        if not credential_data:
            print("❌ ERRORE: Dati vuoti ricevuti")
            raise HTTPException(status_code=400, detail="Dati credenziale vuoti")
        
        # Estrai informazioni principali dalla credenziale
        try:
            credential_id = credential_data.get('metadata', {}).get('credential_id', 'unknown')
            issuer_name = credential_data.get('issuer', {}).get('name', 'Sconosciuto')
            issued_at = credential_data.get('metadata', {}).get('issued_at', 'Sconosciuto')
            student_pseudonym = credential_data.get('subject', {}).get('pseudonym', 'Sconosciuto')
            total_courses = len(credential_data.get('courses', []))
            total_ects = credential_data.get('total_ects_credits', 0)
            
            print(f"🏛️  Università Emittente: {issuer_name}")
            print(f"👤 Studente: {student_pseudonym}")
            print(f"🆔 ID Credenziale: {credential_id}")
            print(f"📅 Data Emissione: {issued_at}")
            print(f"📚 Corsi Inclusi: {total_courses}")
            print(f"🎯 Crediti ECTS: {total_ects}")
            
        except Exception as info_error:
            print(f"⚠️  Attenzione: Impossibile estrarre info credenziale: {info_error}")
            credential_id = f"received_{int(timestamp.timestamp())}"
        
        # Crea nome file univoco e sicuro
        safe_credential_id = str(credential_id).replace("urn:uuid:", "").replace(":", "_").replace("/", "_")
        filename = f"{safe_credential_id}_{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
        file_path = os.path.join(WALLET_DIR, filename)

        # Salva il file JSON con formattazione leggibile
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(credential_data, f, ensure_ascii=False, indent=4)
            
            file_size = os.path.getsize(file_path)
            print(f"💾 File salvato: {filename}")
            print(f"📁 Percorso completo: {os.path.abspath(file_path)}")
            print(f"📊 Dimensione file: {file_size:,} bytes")
            
        except Exception as save_error:
            print(f"❌ ERRORE CRITICO: Impossibile salvare file: {save_error}")
            raise HTTPException(status_code=500, detail=f"Errore salvataggio: {save_error}")
        
        # Aggiorna statistiche
        stats["credentials_received"] += 1
        stats["last_received"] = timestamp
        
        print(f"📈 Totale credenziali ricevute: {stats['credentials_received']}")
        print(f"✅ SUCCESSO! Credenziale acquisita nel wallet via {protocol}")
        print(f"{'='*60}\n")
        
        # Mostra istruzioni per il prossimo passo
        if stats["credentials_received"] == 1:
            print("💡 PROSSIMI PASSI:")
            print("   1. Importa la credenziale nel tuo wallet dal dashboard")
            print("   2. Crea presentazioni verificabili")
            print("   3. Condividi in modo sicuro con divulgazione selettiva")
            print()
        
        # Risposta di successo
        response_data = {
            "status": "success",
            "message": f"Credenziale ricevuta e salvata con successo via {protocol}",
            "wallet_id": WALLET_ID,
            "credential_id": safe_credential_id,
            "filename": filename,
            "timestamp": timestamp.isoformat(),
            "file_path": os.path.abspath(file_path),
            "file_size_bytes": file_size,
            "total_received": stats["credentials_received"],
            "protocol": protocol,
            "secure": USE_HTTPS
        }
        
        return response_data

    except HTTPException:
        raise
    except Exception as e:
        error_msg = f"Errore interno del server: {e}"
        print(f"\n❌ ERRORE CRITICO: {error_msg}")
        print(f"Tipo errore: {type(e).__name__}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=error_msg)

@app.get('/api/credentials')
async def list_credentials():
    """Lista tutte le credenziali ricevute"""
    try:
        credentials = []
        for filename in os.listdir(WALLET_DIR):
            if filename.endswith('.json'):
                file_path = os.path.join(WALLET_DIR, filename)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    credentials.append({
                        "filename": filename,
                        "credential_id": data.get('metadata', {}).get('credential_id'),
                        "issuer": data.get('issuer', {}).get('name'),
                        "student": data.get('subject', {}).get('pseudonym'),
                        "file_path": file_path,
                        "file_size": os.path.getsize(file_path)
                    })
                except Exception:
                    continue
        
        return {
            "wallet_id": WALLET_ID,
            "total_credentials": len(credentials),
            "credentials": credentials,
            "protocol": "HTTPS" if USE_HTTPS else "HTTP"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == '__main__':
    print_banner()
    
    # Configura uvicorn per HTTPS o HTTP
    uvicorn_config = {
        "app": app,
        "host": '0.0.0.0',
        "port": PORT,
        "log_level": "warning",
        "access_log": False
    }
    
    if USE_HTTPS:
        ssl_result = create_ssl_context()
        if ssl_result:
            cert_path, key_path = ssl_result
            uvicorn_config.update({
                "ssl_certfile": cert_path,
                "ssl_keyfile": key_path,
                "ssl_keyfile_password": "Unisa2025"
            })
        else:
            print("❌ HTTPS richiesto ma certificati non disponibili")
            print("🔄 Passaggio a modalità HTTP...")
            USE_HTTPS = False
    
    try:
        uvicorn.run(**uvicorn_config)
    except KeyboardInterrupt:
        print("\n🛑 Servizio interrotto dall'utente")
    except Exception as e:
        print(f"\n❌ Errore avvio servizio: {e}")
        if USE_HTTPS:
            print("💡 Prova a rigenerare i certificati o disabilita HTTPS")
    finally:
        print(f"\n📊 STATISTICHE FINALI:")
        print(f"   Credenziali ricevute: {stats['credentials_received']}")
        if stats['last_received']:
            print(f"   Ultima ricezione: {stats['last_received'].strftime('%d/%m/%Y %H:%M:%S')}")