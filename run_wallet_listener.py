# run_wallet_listener.py - Versione migliorata

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import json
import os
from datetime import datetime
import uvicorn
import socket

# --- CONFIGURAZIONE ---
WALLET_ID = "studente_mariorossi_wallet"
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

# Preparazione dell'ambiente
WALLET_DIR = os.path.join('src', 'credentials', WALLET_ID)
os.makedirs(WALLET_DIR, exist_ok=True)

app = FastAPI(
    title="Student Wallet Listener",
    description="Riceve credenziali accademiche dall'università",
    version="1.0.0"
)

# Abilita CORS per permettere connessioni da altri PC
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In produzione, limitare agli IP specifici
    allow_credentials=True,
    allow_methods=["*"],
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
    print("=" * 80)
    print("🎓 STUDENT WALLET LISTENER - RICEVITORE CREDENZIALI ACCADEMICHE")
    print("=" * 80)
    print(f"✅ Wallet ID: {WALLET_ID}")
    print(f"📁 Directory: {os.path.abspath(WALLET_DIR)}")
    print(f"🌐 Server avviato su:")
    print(f"   • Locale:        http://localhost:8080/api/credential-receiver")
    print(f"   • IP della LAN:  http://{local_ip}:8080/api/credential-receiver")
    print(f"🔍 Endpoint di test: http://{local_ip}:8080/")
    print("=" * 80)
    print("📞 ISTRUZIONI PER L'UNIVERSITÀ:")
    print(f"   Inserire nel campo 'URL Wallet Studente': {local_ip}")
    print("   (oppure l'IP pubblico se su reti diverse)")
    print("=" * 80)
    print("⏳ In attesa di credenziali...")
    print()

@app.get("/")
async def root():
    """Homepage con informazioni sul servizio"""
    local_ip = get_local_ip()
    uptime = datetime.now() - stats["start_time"]
    
    return {
        "status": "🟢 ATTIVO",
        "wallet_id": WALLET_ID,
        "service": "Student Wallet Listener",
        "version": "1.0.0",
        "uptime_seconds": int(uptime.total_seconds()),
        "uptime_human": str(uptime).split('.')[0],
        "credentials_received": stats["credentials_received"],
        "last_received": stats["last_received"].isoformat() if stats["last_received"] else None,
        "endpoint": f"http://{local_ip}:8080/api/credential-receiver",
        "instructions": {
            "for_university": f"Inserire questo IP nel dashboard: {local_ip}",
            "test_connection": f"GET http://{local_ip}:8080/",
            "receive_credential": f"POST http://{local_ip}:8080/api/credential-receiver"
        }
    }

@app.get("/status")
async def status():
    """Endpoint di stato semplice"""
    return {"status": "ok", "service": "wallet-listener", "ready": True}

@app.post('/api/credential-receiver')
async def receive_credential(request: Request):
    """Endpoint principale per ricevere credenziali"""
    
    timestamp = datetime.now()
    print(f"\n{'='*60}")
    print(f"📥 [{timestamp.strftime('%H:%M:%S')}] CREDENZIALE RICEVUTA!")
    print(f"{'='*60}")
    
    try:
        # Ottieni informazioni sulla richiesta
        client_ip = request.client.host
        user_agent = request.headers.get("user-agent", "Sconosciuto")
        
        print(f"🌐 IP Mittente: {client_ip}")
        print(f"🖥️  User Agent: {user_agent}")
        
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
        print(f"✅ SUCCESSO! Credenziale acquisita nel wallet")
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
            "message": "Credenziale ricevuta e salvata con successo",
            "wallet_id": WALLET_ID,
            "credential_id": safe_credential_id,
            "filename": filename,
            "timestamp": timestamp.isoformat(),
            "file_path": os.path.abspath(file_path),
            "file_size_bytes": file_size,
            "total_received": stats["credentials_received"]
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
            "credentials": credentials
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == '__main__':
    print_banner()
    
    try:
        uvicorn.run(
            app, 
            host='0.0.0.0',  # Ascolta su tutte le interfacce
            port=8080,
            log_level="warning",  # Riduce i log di uvicorn per chiarezza
            access_log=False     # Disabilita access log per focus sui nostri messaggi
        )
    except KeyboardInterrupt:
        print("\n🛑 Servizio interrotto dall'utente")
    except Exception as e:
        print(f"\n❌ Errore avvio servizio: {e}")
    finally:
        print(f"\n📊 STATISTICHE FINALI:")
        print(f"   Credenziali ricevute: {stats['credentials_received']}")
        if stats['last_received']:
            print(f"   Ultima ricezione: {stats['last_received'].strftime('%d/%m/%Y %H:%M:%S')}")
        print("👋 Arrivederci!")