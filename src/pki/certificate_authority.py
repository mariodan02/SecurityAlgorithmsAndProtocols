"""Gestione Certificate Authority per il sistema di credenziali accademiche."""

import os
import datetime
import ipaddress
from pathlib import Path
from typing import Dict, Any

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .certificate_manager import CertificateManager
from crypto.foundations import RSAKeyManager

# Configurazione host e porta per OCSP
HOST = "127.0.0.1"
PORT = 5001


class CertificateAuthority:
    """Gestisce la creazione e le operazioni di una Certificate Authority."""

    def __init__(self, root_path: str = "./certificates/ca", ca_password: str = "Unisa2025"):
        """
        Inizializza la Certificate Authority.
        
        Args:
            root_path: Percorso directory root della CA
            ca_password: Password per la chiave privata della CA
        """
        self.root_path = Path(root_path)
        self.ca_password = ca_password
        self.key_path = self.root_path / "private" / "ca_private.pem"
        self.cert_path = self.root_path / "ca_certificate.pem"
        self.index_path = self.root_path / "index.txt"
        self.serial_path = self.root_path / "serial"

        self.key_manager = RSAKeyManager(key_size=4096)
        self.cert_manager = CertificateManager()

        self.private_key: rsa.RSAPrivateKey = None
        self.certificate: x509.Certificate = None

        self._initialize_ca()

    def _initialize_ca(self) -> None:
        """Inizializza la CA, creandola se non esiste."""
        self.root_path.mkdir(parents=True, exist_ok=True)
        (self.root_path / "private").mkdir(exist_ok=True)

        if self.key_path.exists() and self.cert_path.exists():
            self.load_ca()
        else:
            self.create_self_signed_ca()

    def create_self_signed_ca(self, common_name: str = "Academic Credentials Root CA") -> None:
        """
        Crea la chiave privata e il certificato autofirmato per la Root CA.
        
        Args:
            common_name: Nome comune per il certificato CA
        """
        private_key, public_key = self.key_manager.generate_key_pair()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Campania"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Salerno"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Academic Credentials Project"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        # Costruisce il certificato CA con validità di 10 anni
        builder = (x509.CertificateBuilder()
                  .subject_name(subject)
                  .issuer_name(issuer)
                  .public_key(public_key)
                  .serial_number(x509.random_serial_number())
                  .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                  .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + 
                                 datetime.timedelta(days=365 * 10))
                  .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                  .add_extension(
                      x509.AuthorityInformationAccess([
                          x509.AccessDescription(
                              x509.oid.AuthorityInformationAccessOID.OCSP,
                              x509.UniformResourceIdentifier(f"http://{HOST}:{PORT}/ocsp")
                          )
                      ]),
                      critical=False
                  ))

        certificate = builder.sign(private_key, hashes.SHA256())

        self._save_ca_files(private_key, certificate)
        self._initialize_db()

        self.private_key = private_key
        self.certificate = certificate

    def _save_ca_files(self, private_key: rsa.RSAPrivateKey, certificate: x509.Certificate) -> None:
        """Salva i file della CA sul filesystem."""
        password_bytes = self.ca_password.encode('utf-8') if self.ca_password else None
        
        # Salva chiave privata con protezione
        with open(self.key_path, "wb") as f:
            f.write(self.key_manager.serialize_private_key(private_key, password_bytes))
        os.chmod(self.key_path, 0o600)

        # Salva certificato
        with open(self.cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

    def _initialize_db(self) -> None:
        """Inizializza i file di database per la CA."""
        self.index_path.touch(exist_ok=True)
        if not self.serial_path.exists():
            self.serial_path.write_text("1000")

    def load_ca(self) -> None:
        """Carica una CA esistente dal filesystem."""
        try:
            key_data = self.key_path.read_bytes()
            cert_data = self.cert_path.read_bytes()
            
            password_bytes = self.ca_password.encode('utf-8') if self.ca_password else None
            self.private_key = self.key_manager.deserialize_private_key(key_data, password_bytes)
            self.certificate = self.cert_manager.load_certificate_from_bytes(cert_data)
        except Exception as e:
            raise RuntimeError(f"Errore caricamento CA: {e}")

    def sign_certificate(self, csr: x509.CertificateSigningRequest, 
                        days_valid: int = 365) -> x509.Certificate:
        """
        Firma una Certificate Signing Request con la chiave della CA.
        
        Args:
            csr: Certificate Signing Request da firmare
            days_valid: Giorni di validità del certificato
            
        Returns:
            Certificato firmato
        """
        if not self.private_key or not self.certificate:
            raise RuntimeError("La CA non è stata inizializzata correttamente")

        # Ottiene il prossimo numero di serie
        serial_number = int(self.serial_path.read_text())
        self.serial_path.write_text(str(serial_number + 1))

        # Costruisce il certificato
        builder = (x509.CertificateBuilder()
                  .subject_name(csr.subject)
                  .issuer_name(self.certificate.subject)
                  .public_key(csr.public_key())
                  .serial_number(serial_number)
                  .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                  .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + 
                                 datetime.timedelta(days=days_valid)))

        # Aggiunge le estensioni dalla CSR
        for extension in csr.extensions:
            builder = builder.add_extension(extension.value, critical=extension.critical)

        # Aggiunge URL OCSP a tutti i certificati firmati
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(f"http://{HOST}:{PORT}/ocsp")
                )
            ]),
            critical=False
        )

        new_certificate = builder.sign(self.private_key, hashes.SHA256())
        self._update_index(new_certificate)

        return new_certificate

    def _update_index(self, certificate: x509.Certificate) -> None:
        """Aggiorna il file index.txt con i dettagli del nuovo certificato."""
        exp_date = certificate.not_valid_after.strftime('%y%m%d%H%M%SZ')
        serial = hex(certificate.serial_number)[2:].upper()
        subject_dn = certificate.subject.rfc4514_string()

        entry = f"V\t{exp_date}\t\t{serial}\tunknown\t/{subject_dn}\n"

        with open(self.index_path, "a") as f:
            f.write(entry)

    def _get_cert_path(self, entity_info: Dict[str, Any]) -> Path:
        """Determina il percorso del certificato in base al tipo di entità."""
        entity_type = entity_info.get('type', 'university')
        
        path_map = {
            'server': f"./certificates/server/{entity_info['name']}.pem",
            'university': f"./certificates/issued/university_{entity_info['erasmus_code']}_{entity_info['serial']}.pem",
            'student': f"./certificates/students/{entity_info['name']}.pem"
        }
        
        return Path(path_map.get(entity_type, 
                               f"./certificates/issued/{entity_info['name']}_{entity_info['serial']}.pem"))

    def generate_certificate_for_entity(self, entity_info: Dict[str, Any], 
                                       key_size: int = 2048) -> tuple[Path, Path]:
        """
        Genera un certificato per un'entità specifica.
        
        Args:
            entity_info: Informazioni dell'entità
            key_size: Dimensione della chiave in bit
            
        Returns:
            Tuple con percorsi del certificato e della chiave
        """
        entity_name = entity_info["name"]
        cert_path = self._get_cert_path(entity_info)
        key_path = Path(f"./keys/{entity_name}_private.pem")
        
        # Crea le directory necessarie
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Verifica se già esistono
        if cert_path.exists() and key_path.exists():
            return cert_path, key_path

        # Genera coppia di chiavi
        key_manager = RSAKeyManager(key_size=key_size)
        private_key, public_key = key_manager.generate_key_pair()
        key_manager.save_key_pair(private_key, public_key, "./keys", 
                                entity_name, entity_info.get('password'))

        # Costruisce il subject del certificato
        subject_attributes = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, entity_info['country']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, entity_info['organization']),
            x509.NameAttribute(NameOID.COMMON_NAME, entity_info['common_name']),
        ]
        
        # Aggiunge USER_ID per gli studenti
        if entity_info.get('type') == 'student':
            subject_attributes.append(
                x509.NameAttribute(NameOID.USER_ID, entity_info['student_id'])
            )

        subject = x509.Name(subject_attributes)
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)
        
        # Aggiunge Subject Alternative Names se presenti
        if 'sans' in entity_info:
            san_list = []
            for san in entity_info['sans']:
                if san['type'] == 'DNS':
                    san_list.append(x509.DNSName(san['value']))
                elif san['type'] == 'IP':
                    san_list.append(x509.IPAddress(ipaddress.ip_address(san['value'])))
            
            if san_list:
                csr_builder = csr_builder.add_extension(
                    x509.SubjectAlternativeName(san_list), critical=False
                )
        
        # Crea CSR e firma il certificato
        csr = csr_builder.sign(private_key, hashes.SHA256())
        entity_cert = self.sign_certificate(csr, entity_info.get('validity_days', 365))
        self.cert_manager.save_certificate_to_file(entity_cert, str(cert_path))
        
        return cert_path, key_path

    def generate_certificate_for_student(self, student_info: Dict[str, Any]) -> tuple[Path, Path]:
        """Genera un certificato per uno studente."""
        student_info['type'] = 'student'
        return self.generate_certificate_for_entity(student_info, key_size=2048)