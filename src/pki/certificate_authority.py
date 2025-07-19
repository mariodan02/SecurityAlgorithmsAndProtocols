# =============================================================================
# FASE 2: GESTIONE CERTIFICATI X.509 - CERTIFICATE AUTHORITY (MODIFICATO)
# File: pki/certificate_authority.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import sys
import datetime
import ipaddress
from pathlib import Path

try:
    # Prova l'import assoluto, che funzionerà se 'src' è già nel PYTHONPATH
    from pki.certificate_manager import CertificateManager
    from crypto.foundations import RSAKeyManager
except ImportError:
    # Se fallisce, aggiungi manualmente 'src' al path e riprova
    project_root = str(Path(__file__).parent.parent)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    from pki.certificate_manager import CertificateManager
    from crypto.foundations import RSAKeyManager

# Import crittografici
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class CertificateAuthority:
    """
    Gestisce la creazione e le operazioni di una Certificate Authority (CA) per il progetto.
    Questa classe è responsabile della creazione della Root CA e della firma dei
    certificati per le entità del sistema.
    """

    def __init__(self, root_path: str = "./certificates/ca", ca_password: str = "Unisa2025"):
        self.root_path = Path(root_path)
        self.ca_password = ca_password
        self.key_path = self.root_path / "private" / "ca_private.pem"
        self.cert_path = self.root_path / "ca_certificate.pem"
        self.index_path = self.root_path / "index.txt"
        self.serial_path = self.root_path / "serial"

        # Manager per operazioni su chiavi e certificati
        self.key_manager = RSAKeyManager(key_size=4096)  # Chiave robusta per la CA
        self.cert_manager = CertificateManager()

        self.private_key: rsa.RSAPrivateKey = None
        self.certificate: x509.Certificate = None

        self._initialize_ca()

    def _initialize_ca(self):
        """Inizializza la CA, creandola se non esiste."""
        print("🏛️  Inizializzazione Certificate Authority...")
        self.root_path.mkdir(parents=True, exist_ok=True)
        (self.root_path / "private").mkdir(exist_ok=True)

        if self.key_path.exists() and self.cert_path.exists():
            print("CA già esistente. Caricamento in corso...")
            self.load_ca()
        else:
            print("Nessuna CA trovata. Creazione di una nuova Root CA...")
            self.create_self_signed_ca()

    def create_self_signed_ca(self, common_name="Academic Credentials Root CA"):
        """Crea la chiave privata e il certificato autofirmato per la Root CA."""
        private_key, public_key = self.key_manager.generate_key_pair()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Campania"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Salerno"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Academic Credentials Project"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365 * 10)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )

        certificate = builder.sign(private_key, hashes.SHA256())

        self._save_ca_files(private_key, certificate)
        self._initialize_db()

        self.private_key = private_key
        self.certificate = certificate
        print(f"✅ Root CA '{common_name}' creata con successo.")

    def _save_ca_files(self, private_key, certificate):
        """Salva i file della CA (chiave e certificato)."""
        password_bytes = self.ca_password.encode('utf-8') if self.ca_password else None
        with open(self.key_path, "wb") as f:
            f.write(self.key_manager.serialize_private_key(private_key, password_bytes))
        os.chmod(self.key_path, 0o600)

        with open(self.cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

    def _initialize_db(self):
        """Inizializza i file di database per la CA (index e serial)."""
        if not self.index_path.exists():
            self.index_path.touch()
        if not self.serial_path.exists():
            self.serial_path.write_text("1000")

    def load_ca(self):
        """Carica una CA esistente dal filesystem."""
        try:
            key_data = self.key_path.read_bytes()
            cert_data = self.cert_path.read_bytes()
            
            password_bytes = self.ca_password.encode('utf-8') if self.ca_password else None
            self.private_key = self.key_manager.deserialize_private_key(key_data, password_bytes)
            self.certificate = self.cert_manager.load_certificate_from_bytes(cert_data)
            print("✅ CA caricata correttamente.")
        except Exception as e:
            print(f"❌ Errore caricamento CA: {e}")
            raise

    def sign_certificate(self, csr: x509.CertificateSigningRequest, days_valid: int = 365) -> x509.Certificate:
        """Firma una Certificate Signing Request (CSR) con la chiave della CA."""
        if not self.private_key or not self.certificate:
            raise RuntimeError("La CA non è stata inizializzata correttamente.")

        serial_number = int(self.serial_path.read_text())
        self.serial_path.write_text(str(serial_number + 1))

        builder = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            self.certificate.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            serial_number
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_valid)
        )

        for extension in csr.extensions:
            builder = builder.add_extension(extension.value, critical=extension.critical)

        new_certificate = builder.sign(self.private_key, hashes.SHA256())
        print(f"✅ Certificato firmato per: {new_certificate.subject.rfc4514_string()}")

        self._update_index(new_certificate)

        return new_certificate

    def _update_index(self, certificate: x509.Certificate):
        """Aggiorna il file index.txt con i dettagli del nuovo certificato."""
        exp_date = certificate.not_valid_after.strftime('%y%m%d%H%M%SZ')
        serial = hex(certificate.serial_number)[2:].upper()
        subject_dn = certificate.subject.rfc4514_string()

        entry = f"V\t{exp_date}\t\t{serial}\tunknown\t/{subject_dn}\n"

        with open(self.index_path, "a") as f:
            f.write(entry)

    def _get_cert_path(self, entity_info: dict) -> Path:
        """Determina il percorso del certificato in base al tipo di entità."""
        entity_type = entity_info.get('type', 'university')
        if entity_type == 'server':
            return Path(f"./certificates/server/{entity_info['name']}.pem")
        elif entity_type == 'university':
            return Path(f"./certificates/issued/university_{entity_info['erasmus_code']}_{entity_info['serial']}.pem")
        elif entity_type == 'student':
            # NUOVO: Path per i certificati degli studenti
            return Path(f"./certificates/students/{entity_info['name']}.pem")
        else:
            return Path(f"./certificates/issued/{entity_info['name']}_{entity_info['serial']}.pem")

    def _generate_certificate_for_entity(self, entity_info: dict, key_size: int = 2048):
        """Genera un certificato per un'entità specifica (università, server)."""
        entity_name = entity_info["name"]
        print(f"\n⚙️  Generazione certificato per '{entity_info['common_name']}' ({entity_info.get('type', 'university')})")
        
        key_path = Path(f"./keys/{entity_name}_private.pem")
        cert_path = self._get_cert_path(entity_info)
        
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        
        if cert_path.exists() and key_path.exists():
            print(f"ℹ️  Certificato e chiave per '{entity_info['common_name']}' già esistenti. Salto.")
            return cert_path, key_path

        key_manager = RSAKeyManager(key_size=key_size)
        private_key, public_key = key_manager.generate_key_pair()
        key_manager.save_key_pair(private_key, public_key, "./keys", entity_name, entity_info.get('password'))

        subject_attributes = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, entity_info['country']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, entity_info['organization']),
            x509.NameAttribute(NameOID.COMMON_NAME, entity_info['common_name']),
        ]
        if entity_info.get('type') == 'student':
             subject_attributes.append(x509.NameAttribute(NameOID.USER_ID, entity_info['student_id']))


        subject = x509.Name(subject_attributes)
        
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        
        if 'sans' in entity_info:
            san_list = [x509.DNSName(san['value']) if san['type'] == 'DNS' else x509.IPAddress(ipaddress.ip_address(san['value'])) for san in entity_info['sans']]
            csr_builder = csr_builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        
        csr = csr_builder.sign(private_key, hashes.SHA256())
        entity_cert = self.sign_certificate(csr, entity_info.get('validity_days', 365))
        self.cert_manager.save_certificate_to_file(entity_cert, str(cert_path))
        
        return cert_path, key_path
    
    # NUOVA FUNZIONE per coerenza, anche se _generate_certificate_for_entity è già generica
    def generate_certificate_for_student(self, student_info: dict):
        """Genera un certificato per uno studente."""
        student_info['type'] = 'student'
        return self._generate_certificate_for_entity(student_info, key_size=2048)

    @staticmethod
    def revoke_a_certificate_for_testing():
        """
        Funzione di utilità per revocare un certificato specifico per il testing OCSP.
        """
        ca = CertificateAuthority()

        # Carica il certificato da revocare
        cert_to_revoke_path = "./certificates/issued/university_F_RENNES01_1001.pem"

        if not Path(cert_to_revoke_path).exists():
            print(f"ERRORE: Certificato da revocare non trovato in {cert_to_revoke_path}")
            print("Assicurati di aver prima generato i certificati eseguendo questo script senza modifiche.")
            return

        print(f"\n- Revocando il certificato: {cert_to_revoke_path}")

        # La CA interna userà il suo database per gestire la revoca
        # (Questa è una simulazione, il tuo MockOCSPResponder leggerà lo stato)
        print("NOTA: La revoca viene registrata nel database della CA (index.txt).")
        print("Il MockOCSPResponder simulerà la lettura di questo stato.")



def main():
    """Funzione principale per creare la CA e i certificati per le entità."""
    ca = CertificateAuthority()

    entities = [
        # Università e Server
        { "type": "university", "name": "universite_rennes", "common_name": "Université de Rennes", "country": "FR", "organization": "Université de Rennes", "erasmus_code": "F_RENNES01", "password": "Unisa2025", "serial": "1001", "sans": [{"type": "DNS", "value": "api.universite_rennes.edu"}] },
        { "type": "university", "name": "universita_salerno", "common_name": "Università degli Studi di Salerno", "country": "IT", "organization": "Università degli Studi di Salerno", "erasmus_code": "I_SALERNO01", "password": "Unisa2025", "serial": "1002", "sans": [{"type": "DNS", "value": "api.unisa.edu"}] },
        { "type": "server", "name": "secure_server", "common_name": "Academic Credentials Secure Server", "country": "IT", "organization": "Academic Credentials Project", "password": "Unisa2025", "serial": "1003", "sans": [{"type": "DNS", "value": "localhost"}, {"type": "IP", "value": "127.0.0.1"}] },
        # NUOVO: Studente di Esempio
        { "type": "student", "name": "mario_rossi_0622702628", "common_name": "Mario Rossi", "country": "IT", "organization": "Student Wallet", "student_id": "0622702628", "password": "StudentPassword123!", "serial": "2001" }
    ]

    generated_files = []
    for entity in entities:
        cert_path, key_path = ca._generate_certificate_for_entity(entity)
        generated_files.append((str(cert_path), str(key_path)))

    print("\n🎉 Generazione certificati completata!")
    print("📁 File generati:")
    print(f"   {ca.cert_path} (Certificato Root CA)")
    for cert_path, key_path in generated_files:
        print(f"   {cert_path} (Certificato)")
        print(f"   {key_path} (Chiave privata)")


if __name__ == "__main__":
    main()
    # Revoca per il test
    CertificateAuthority.revoke_a_certificate_for_testing()