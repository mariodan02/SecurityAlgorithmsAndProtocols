# run_wallet_listener_fastapi.py

from fastapi import FastAPI, Request, HTTPException
import json
import os
from datetime import datetime
import uvicorn

# --- CONFIGURAZIONE ---
WALLET_ID = "studente_mariorossi_wallet"
# --------------------

# Preparazione dell'ambiente
WALLET_DIR = os.path.join('src', 'credentials', WALLET_ID)
os.makedirs(WALLET_DIR, exist_ok=True)

app = FastAPI()

print("="*60)
print(f"✅ Wallet Listener (FastAPI) pronto per '{WALLET_ID}'")
print(f"🚀 In ascolto su http://0.0.0.0:8080/api/credential-receiver")
print("In attesa che la credenziale venga emessa dal server...")
print("="*60)

@app.post('/api/credential-receiver')
async def receive_credential(request: Request):
    """Questo endpoint riceve la credenziale via POST e la salva."""
    
    print(f"\n[{datetime.now()}] --- 📥 Richiesta POST RICEVUTA! ---")
    
    try:
        # Recupera i dati JSON dalla richiesta
        credential_data = await request.json()
        print("📄 Dati ricevuti nel JSON:")
        print(json.dumps(credential_data, indent=2))

        # Crea nome file univoco
        credential_id = credential_data.get('id', f"received_{int(datetime.now().timestamp())}")
        safe_credential_id = credential_id.replace("urn:uuid:", "").replace(":", "_")
        file_path = os.path.join(WALLET_DIR, f"{safe_credential_id}.json")

        # Salva il file JSON
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(credential_data, f, ensure_ascii=False, indent=4)
            
        print(f"\n✅ Cazzo, ce l'abbiamo fatta! Credenziale salvata in:")
        print(f"   -> {os.path.abspath(file_path)}")
        
        return {"status": "success"}

    except Exception as e:
        print(f"\n❌ ERRORE: Qualcosa è andato storto: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == '__main__':
    uvicorn.run(
        app, 
        host='0.0.0.0', 
        port=8080,
        # Facoltativo: migliora i log per sviluppo
        log_config={
            "version": 1,
            "formatters": {
                "default": {
                    "()": "uvicorn.logging.DefaultFormatter",
                    "fmt": "%(levelprefix)s %(message)s",
                }
            },
            "handlers": {
                "default": {
                    "formatter": "default",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stderr",
                },
            },
            "loggers": {
                "uvicorn": {"handlers": ["default"], "level": "INFO"},
            },
        }
    )