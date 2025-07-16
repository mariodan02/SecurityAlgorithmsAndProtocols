import logging
from logging.handlers import RotatingFileHandler
import datetime

# Imposta un logger dedicato per gli eventi di sicurezza
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_file = 'security_events.log'

# Utilizza un gestore di file a rotazione per evitare che i file di log diventino troppo grandi
handler = RotatingFileHandler(log_file, maxBytes=1024*1024, backupCount=5)
handler.setFormatter(log_formatter)

security_logger = logging.getLogger('security_logger')
security_logger.setLevel(logging.INFO)
security_logger.addHandler(handler)

class SecurityEvent:
    """Definisce le costanti per i diversi tipi di eventi di sicurezza."""
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    CREDENTIAL_ISSUED = "CREDENTIAL_ISSUED"
    CREDENTIAL_VERIFIED_SUCCESS = "CREDENTIAL_VERIFIED_SUCCESS"
    CREDENTIAL_VERIFIED_FAILURE = "CREDENTIAL_VERIFIED_FAILURE"
    CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
    REVOKED_CREDENTIAL_USED = "REVOKED_CREDENTIAL_USED"
    CERTIFICATE_REVOKED = "CERTIFICATE_REVOKED"
    SYSTEM_ERROR = "SYSTEM_ERROR"

class SecurityMonitor:
    """
    Una semplice utility per il monitoraggio e la registrazione della sicurezza.
    Può essere estesa con meccanismi di allerta (es. invio di email).
    """

    @staticmethod
    def log_event(event_type: str, details: dict):
        """
        Registra un evento di sicurezza con dettagli strutturati.

        Args:
            event_type (str): Il tipo di evento (dalla classe SecurityEvent).
            details (dict): Un dizionario contenente informazioni rilevanti sull'evento.
                            Le chiavi comuni potrebbero essere 'username', 'ip_address', 'credential_hash', ecc.
        """
        log_message = f"Event: {event_type} | Details: {details}"
        security_logger.info(log_message)
        print(f"SECURITY LOG: {log_message}") # Stampa anche sulla console per una visibilità immediata

    @staticmethod
    def check_for_alerts(log_file_path=log_file):
        """
        Una semplice funzione di controllo degli avvisi che potrebbe essere eseguita periodicamente.
        Questo è un esempio di base; i sistemi reali utilizzerebbero strumenti più sofisticati.
        """
        # Esempio: Avvisa in caso di 3 o più accessi falliti dallo stesso IP negli ultimi 5 minuti.
        recent_failures = {}
        five_minutes_ago = datetime.datetime.now() - datetime.timedelta(minutes=5)

        try:
            with open(log_file_path, 'r') as f:
                for line in f:
                    if "LOGIN_FAILURE" in line:
                        try:
                            # Parsing di base, può essere migliorato con una registrazione strutturata (es. JSON)
                            timestamp_str = line.split(' - ')[0]
                            event_time = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
                            
                            if event_time > five_minutes_ago:
                                ip = line.split("'ip_address': '")[1].split("'")[0]
                                recent_failures[ip] = recent_failures.get(ip, 0) + 1
                        except (ValueError, IndexError):
                            continue # Ignora le righe di log malformate
            
            for ip, count in recent_failures.items():
                if count >= 3:
                    alert_details = {"ip_address": ip, "failed_attempts": count}
                    SecurityMonitor.log_event("ALERT_BRUTE_FORCE_SUSPECTED", alert_details)

        except FileNotFoundError:
            pass # Nessun file di log ancora presente

# Esempio di come utilizzare il monitor nella tua app Flask (es. in web/dashboard.py)
if __name__ == '__main__':
    # --- DIMOSTRAZIONE ---
    
    # Simula un accesso riuscito
    SecurityMonitor.log_event(SecurityEvent.LOGIN_SUCCESS, {"username": "mario.rossi", "ip_address": "192.168.1.10"})

    # Simula un accesso fallito
    SecurityMonitor.log_event(SecurityEvent.LOGIN_FAILURE, {"username": "unknown_user", "ip_address": "10.0.0.5"})
    
    # Simula una verifica di credenziale
    SecurityMonitor.log_event(
        SecurityEvent.CREDENTIAL_VERIFIED_SUCCESS, 
        {"verifier": "did:example:unirennes", "credential_hash": "abc123def456...", "ip_address": "143.204.12.34"}
    )
    
    # Simula accessi multipli falliti per attivare un avviso
    for i in range(3):
        SecurityMonitor.log_event(SecurityEvent.LOGIN_FAILURE, {"username": "admin", "ip_address": "8.8.8.8"})
    
    # Controlla la presenza di avvisi
    SecurityMonitor.check_for_alerts()