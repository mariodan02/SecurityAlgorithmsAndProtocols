import subprocess
import sys
import time
import os

def run_system():
    """Avvia dashboard e secure server contemporaneamente"""
    processes = []
    
    # Comandi da eseguire
    commands = [
        [sys.executable, "src/web/dashboard.py"],
        [sys.executable, "src/communication/secure_server.py"]
    ]
    
    # Avvia i processi
    for cmd in commands:
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        processes.append(subprocess.Popen(
            cmd, 
            stdout=sys.stdout, 
            stderr=sys.stderr,
            env=env
        ))
        time.sleep(2)  # Attesa tra un avvio e l'altro
    
    # Attesa terminazione
    try:
        for p in processes:
            p.wait()
    except KeyboardInterrupt:
        for p in processes:
            p.terminate()

if __name__ == "__main__":
    run_system()