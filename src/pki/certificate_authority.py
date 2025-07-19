"""Gestione Certificate Authority per il sistema di credenziali accademiche."""

import os
import sys
import datetime
import ipaddress
from pathlib import Path
from typing import Dict, Any, Tuple

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pki.certificate_manager import CertificateManager
from crypto.foundations import RSAKeyManager

HOST = "127.0.0.1"
PORT = 5001


class CertificateAuthority:
    """Gestisce le operazioni di una Certificate Authority."""

    def __init__(self, root_path: str = "./certificates/ca", ca_password: str = "Unisa2025"):
        self.root_path = Path(root_path)
        self.ca_password = ca_password
        self.key_path = self.root_path / "private" / "ca_private.pem"
        self.cert_path = self.root_path / "ca_certificate.pem"
        self.index_path = self.root_path / "index.txt"
        self.serial_path = self.root_path / "serial"

        self.key_manager = RSAKeyManager(key_size=4096)
        self.cert_manager = CertificateManager()

        self.private_key = None
        self.certificate = None

        self._initialize_ca()

    def _initialize_ca(self) -> None:
        """Carica o crea una nuova CA."""
        self.root_path.mkdir(parents=True, exist_ok=True)
        (self.root_path / "private").mkdir(exist_ok=True)

        if self.key_path.exists() and self.cert_path.exists():
            print("✅ CA esistente - caricamento in corso")
            self.load_ca()
        else:
            print("✨ Creazione nuova Root CA")
            self.create_self_signed_ca()
            print("✅ Root CA creata con successo")

    def create_self_signed_ca(self, common_name: str = "Academic Credentials Root CA") -> None:
        """Crea una nuova CA autofirmata."""
        private_key, public_key = self.key_manager.generate_key_pair()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Campania"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Salerno"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Academic Credentials Project"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.AuthorityInformationAccess([
                    x509.AccessDescription(
                        x509.oid.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(f"http://{HOST}:{PORT}/ocsp")
                    )
                ]),
                critical=False
            )
        )

        certificate = builder.sign(private_key, hashes.SHA256())
        self._save_ca_files(private_key, certificate)
        self._initialize_db()
        self.private_key = private_key
        self.certificate = certificate

    def _save_ca_files(self, private_key: rsa.RSAPrivateKey, certificate: x509.Certificate) -> None:
        """Salva chiave privata e certificato della CA."""
        password_bytes = self.ca_password.encode() if self.ca_password else None
        self.key_path.write_bytes(
            self.key_manager.serialize_private_key(private_key, password_bytes)
        )
        self.key_path.chmod(0o600)
        self.cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        print(f"🔑 Chiave CA salvata: {self.key_path}")
        print(f"📜 Certificato CA salvato: {self.cert_path}")

    def _initialize_db(self) -> None:
        """Inizializza i file di database della CA."""
        self.index_path.touch(exist_ok=True)
        if not self.serial_path.exists():
            self.serial_path.write_text("1000")
        print("🗄️ Database CA inizializzato")

    def load_ca(self) -> None:
        """Carica la CA esistente da disco."""
        try:
            password_bytes = self.ca_password.encode() if self.ca_password else None
            self.private_key = self.key_manager.deserialize_private_key(
                self.key_path.read_bytes(), password_bytes
            )
            self.certificate = self.cert_manager.load_certificate_from_bytes(
                self.cert_path.read_bytes()
            )
            print(f"✅ CA caricata correttamente - SN: {self.certificate.serial_number}")
        except Exception as e:
            raise RuntimeError(f"Errore caricamento CA: {e}")

    def sign_certificate(self, csr: x509.CertificateSigningRequest, days_valid: int = 365) -> x509.Certificate:
        """Firma una Certificate Signing Request."""
        if not self.private_key or not self.certificate:
            raise RuntimeError("CA non inizializzata")

        serial_number = int(self.serial_path.read_text())
        self.serial_path.write_text(str(serial_number + 1))

        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.certificate.subject)
            .public_key(csr.public_key())
            .serial_number(serial_number)
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days_valid))
        )

        for ext in csr.extensions:
            builder = builder.add_extension(ext.value, critical=ext.critical)

        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(f"http://{HOST}:{PORT}/ocsp")
                )
            ]),
            critical=False
        )

        certificate = builder.sign(self.private_key, hashes.SHA256())
        self._update_index(certificate)
        print(f"📝 Firmato certificato SN: {serial_number} - Valido {days_valid} giorni")
        return certificate

    def _update_index(self, certificate: x509.Certificate) -> None:
        """Aggiorna il database dei certificati emessi."""
        exp_date = certificate.not_valid_after_utc.strftime('%y%m%d%H%M%SZ')
        serial = hex(certificate.serial_number)[2:].upper()
        subject_dn = certificate.subject.rfc4514_string()
        with self.index_path.open("a") as f:
            f.write(f"V\t{exp_date}\t\t{serial}\tunknown\t/{subject_dn}\n")

    def _get_cert_path(self, entity_info: Dict[str, Any]) -> Path:
        """Determina il percorso del certificato in base al tipo di entità."""
        entity_type = entity_info['type']
        if entity_type == 'server':
            return Path(f"./certificates/server/{entity_info['name']}.pem")
        elif entity_type == 'university':
            return Path(f"./certificates/issued/university_{entity_info['country']}_{entity_info['erasmus_code']}_{entity_info['serial']}.pem")
        elif entity_type == 'student':
            return Path(f"./certificates/students/{entity_info['name']}_{entity_info['student_id']}.pem")
        else:
            raise ValueError(f"Tipo entità non valido: {entity_type}")

    def generate_certificate_for_entity(self, entity_info: Dict[str, Any], key_size: int = 2048) -> Tuple[Path, Path]:
        """Genera certificato e chiave privata per un'entità."""
        entity_name = entity_info["name"]
        cert_path = self._get_cert_path(entity_info)
        key_path = Path(f"./keys/{entity_name}_private.pem")
        
        if cert_path.exists() and key_path.exists():
            print(f"⏩ Certificato esistente per '{entity_name}' - operazione saltata")
            return cert_path, key_path

        cert_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.parent.mkdir(parents=True, exist_ok=True)

        # Generazione chiavi
        print(f"🔑 Generazione chiavi per: {entity_name}")
        key_mgr = RSAKeyManager(key_size=key_size)
        private_key, public_key = key_mgr.generate_key_pair()
        key_mgr.save_key_pair(
            private_key, 
            public_key, 
            "./keys", 
            entity_name, 
            entity_info.get('password')
        )

        # Costruzione CSR
        subject_attrs = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, entity_info['country']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, entity_info['organization']),
            x509.NameAttribute(NameOID.COMMON_NAME, entity_info['common_name']),
        ]
        
        if entity_info['type'] == 'student':
            subject_attrs.append(x509.NameAttribute(NameOID.USER_ID, entity_info['student_id']))

        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(subject_attrs))
        
        # Gestione SANs
        sans = entity_info.get('sans', [])
        if sans:
            san_list = []
            for san in sans:
                if san['type'] == 'DNS':
                    san_list.append(x509.DNSName(san['value']))
                elif san['type'] == 'IP':
                    san_list.append(x509.IPAddress(ipaddress.ip_address(san['value'])))
            csr_builder = csr_builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        
        csr = csr_builder.sign(private_key, hashes.SHA256())
        cert = self.sign_certificate(csr, entity_info.get('validity_days', 365))
        self.cert_manager.save_certificate_to_file(cert, str(cert_path))
        print(f"✅ Certificato emesso: {cert_path}")
        
        return cert_path, key_path


if __name__ == "__main__":
    print("\n" + "="*50)
    print("🔐 CERTIFICATE AUTHORITY - AVVIO PROCESSO")
    print("="*50)
    
    ca = CertificateAuthority()

    entities = [
        {
            "type": "university", "name": "universite_rennes", "country": "FR",
            "organization": "Université de Rennes", "common_name": "Université de Rennes",
            "erasmus_code": "RENNES01", "serial": "1001", "password": "Unisa2025"
        },
        {
            "type": "university", "name": "universita_di_salerno", "country": "IT",
            "organization": "Università degli Studi di Salerno", "common_name": "Università di Salerno",
            "erasmus_code": "SALERNO", "serial": "2001", "password": "Unisa2025"
        },
        {
            "type": "student", "name": "mario_rossi", "country": "IT",
            "organization": "Student Wallet", "common_name": "Mario Rossi",
            "student_id": "0622702628", "password": "StudentPassword123!"
        },
        {
            "type": "server", "name": "secure_server", "country": "IT",
            "organization": "Academic Credentials System", "common_name": "localhost",
            "password": "Unisa2025",
            "sans": [{"type": "DNS", "value": "localhost"}, {"type": "IP", "value": "127.0.0.1"}]
        }
    ]

    print("\n🏫 Avvio emissione certificati:")
    for i, entity in enumerate(entities, 1):
        print(f"\n[{i}/{len(entities)}] Processo: {entity['name']} ({entity['type']})")
        cert_path, key_path = ca.generate_certificate_for_entity(entity)
        print(f"   • Certificato: {cert_path}")
        print(f"   • Chiave privata: {key_path}")

    print("\n" + "="*50)
    print(f"✅ TUTTI I CERTIFICATI SONO STATI EMESSI ({len(entities)} entità)")
    print("="*50 + "\n")