# =============================================================================
# FASE 2: GESTIONE CERTIFICATI X.509 - CERTIFICATE AUTHORITY
# File: pki/certificate_authority.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import json
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict

# Cryptography imports
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import ipaddress

# Import crypto foundations (assumendo che sia nella directory crypto/)
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from crypto.foundations import RSAKeyManager, CryptoUtils
except ImportError:
    print("⚠️  Assicurati che crypto/foundations.py sia presente nel progetto")
    print("   Percorso atteso: ../crypto/foundations.py")
    raise


# =============================================================================
# 1. STRUTTURE DATI PER CERTIFICATI
# =============================================================================

@dataclass
class UniversityInfo:
    """Informazioni università per certificazione"""
    name: str                    # Nome completo università
    country: str                 # Paese
    erasmus_code: str           # Codice Erasmus (es. F RENNES01)
    legal_name: str             # Denominazione legale
    tax_id: str                 # Partita IVA / Tax ID
    address: str                # Indirizzo fisico
    city: str                   # Città
    state_province: str         # Stato/Provincia
    postal_code: str            # CAP
    email: str                  # Email istituzionale
    website: str                # Sito web ufficiale
    accreditation_body: str     # Ente di accreditamento
    accreditation_number: str   # Numero accreditamento
    
    def to_x509_name(self) -> x509.Name:
        """Converte in x509.Name per il certificato"""
        return x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state_province),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.city),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.legal_name),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Academic Credentials Department"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.name),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.email),
        ])


@dataclass
class CertificateRevocationInfo:
    """Informazioni di revoca certificato"""
    certificate_serial: str     # Numero seriale certificato
    revocation_time: datetime.datetime  # Data/ora revoca
    reason_code: int           # Codice motivo revoca
    reason_description: str    # Descrizione motivo
    revoked_by: str           # Chi ha effettuato la revoca
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario per serializzazione"""
        data = asdict(self)
        data['revocation_time'] = self.revocation_time.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CertificateRevocationInfo':
        """Crea istanza da dizionario"""
        data['revocation_time'] = datetime.datetime.fromisoformat(data['revocation_time'])
        return cls(**data)


# =============================================================================
# 2. CERTIFICATE AUTHORITY PRINCIPALE
# =============================================================================

class AcademicCertificateAuthority:
    """Certificate Authority per il sistema di credenziali accademiche"""
    
    # Codici standard per revoca certificati (RFC 5280)
    REVOCATION_REASONS = {
        0: "unspecified",
        1: "keyCompromise", 
        2: "cACompromise",
        3: "affiliationChanged",
        4: "superseded",
        5: "cessationOfOperation",
        6: "certificateHold",
        8: "removeFromCRL",
        9: "privilegeWithdrawn",
        10: "aACompromise"
    }
    
    def __init__(self, ca_name: str = "Academic Credentials CA", 
                 key_size: int = 4096, 
                 validity_years: int = 10):
        """
        Inizializza la Certificate Authority
        
        Args:
            ca_name: Nome della CA
            key_size: Dimensione chiave RSA per CA (4096 consigliato)
            validity_years: Validità certificati CA in anni
        """
        self.ca_name = ca_name
        self.key_size = key_size
        self.validity_years = validity_years
        self.backend = default_backend()
        
        # Gestori utilità
        self.key_manager = RSAKeyManager(key_size)
        self.crypto_utils = CryptoUtils()
        
        # Storage paths
        self.ca_dir = Path("./certificates/ca")
        self.issued_dir = Path("./certificates/issued")
        self.revoked_dir = Path("./certificates/revoked")
        
        # Crea directory se non esistono
        for directory in [self.ca_dir, self.issued_dir, self.revoked_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Database interno
        self.issued_certificates: Dict[str, Dict] = {}  # serial -> info
        self.revoked_certificates: Dict[str, CertificateRevocationInfo] = {}
        self.serial_counter = 1000  # Contatore numeri seriali
        
        # Chiavi e certificato CA
        self.ca_private_key: Optional[rsa.RSAPrivateKey] = None
        self.ca_public_key: Optional[rsa.RSAPublicKey] = None
        self.ca_certificate: Optional[x509.Certificate] = None
        
        print(f"🏛️  Certificate Authority inizializzata: {ca_name}")
        print(f"   Key Size: {key_size} bit")
        print(f"   Validità: {validity_years} anni")
    
    def initialize_ca(self, force_recreate: bool = False) -> bool:
        """
        Inizializza la CA creando il certificato root self-signed
        
        Args:
            force_recreate: Se True, ricrea CA anche se esistente
            
        Returns:
            True se CA inizializzata con successo
        """
        ca_cert_path = self.ca_dir / "ca_certificate.pem"
        ca_key_path = self.ca_dir / "ca_private_key.pem"
        
        # Controlla se CA già esiste
        if not force_recreate and ca_cert_path.exists() and ca_key_path.exists():
            try:
                self._load_existing_ca()
                print("✅ CA esistente caricata con successo")
                return True
            except Exception as e:
                print(f"⚠️  Errore caricamento CA esistente: {e}")
                print("   Procedo con ricreazione...")
        
        try:
            print("🔨 Creazione nuova Certificate Authority...")
            
            # 1. Genera chiavi CA
            print("   1️⃣ Generazione chiavi CA...")
            self.ca_private_key, self.ca_public_key = self.key_manager.generate_key_pair()
            
            # 2. Crea certificato root self-signed
            print("   2️⃣ Creazione certificato root...")
            self.ca_certificate = self._create_ca_certificate()
            
            # 3. Salva chiavi e certificato
            print("   3️⃣ Salvataggio chiavi e certificato...")
            self._save_ca_credentials()
            
            # 4. Inizializza database certificati
            print("   4️⃣ Inizializzazione database...")
            self._load_certificates_database()
            
            print("✅ Certificate Authority creata con successo!")
            self._print_ca_info()
            
            return True
            
        except Exception as e:
            print(f"❌ Errore inizializzazione CA: {e}")
            return False
    
    def _create_ca_certificate(self) -> x509.Certificate:
        """Crea il certificato root self-signed della CA"""
        
        # Subject e Issuer (stesso per certificato self-signed)
        ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "EU"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Europe"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Academic Network"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "European Academic Credentials Authority"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name),
        ])
        
        # Validità
        not_valid_before = datetime.datetime.utcnow()
        not_valid_after = not_valid_before + datetime.timedelta(days=365 * self.validity_years)
        
        # Numero seriale univoco
        serial_number = int(self.crypto_utils.sha256_hash_string(
            f"{self.ca_name}_{not_valid_before.isoformat()}"
        )[:16], 16)
        
        # Builder certificato
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(ca_subject)
        builder = builder.issuer_name(ca_subject)  # Self-signed
        builder = builder.public_key(self.ca_public_key)
        builder = builder.serial_number(serial_number)
        builder = builder.not_valid_before(not_valid_before)
        builder = builder.not_valid_after(not_valid_after)
        
        # Estensioni critiche per CA
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0),  # CA con path length 0
            critical=True,
        )
        
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,     # Firma certificati
                crl_sign=True,          # Firma CRL
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        
        # Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.ca_public_key),
            critical=False,
        )
        
        # Firma il certificato con la propria chiave privata
        certificate = builder.sign(self.ca_private_key, hashes.SHA256(), self.backend)
        
        return certificate
    
    def _save_ca_credentials(self):
        """Salva chiavi e certificato CA su filesystem"""
        
        # Salva chiave privata (con password)
        ca_password = "AcademicCA2025!SecureKey"  # In produzione: generare casualmente
        private_pem = self.key_manager.serialize_private_key(
            self.ca_private_key, 
            ca_password.encode('utf-8')
        )
        
        ca_key_path = self.ca_dir / "ca_private_key.pem"
        with open(ca_key_path, 'wb') as f:
            f.write(private_pem)
        os.chmod(ca_key_path, 0o600)  # Solo lettura proprietario
        
        # Salva chiave pubblica
        public_pem = self.key_manager.serialize_public_key(self.ca_public_key)
        with open(self.ca_dir / "ca_public_key.pem", 'wb') as f:
            f.write(public_pem)
        
        # Salva certificato CA
        cert_pem = self.ca_certificate.public_bytes(serialization.Encoding.PEM)
        with open(self.ca_dir / "ca_certificate.pem", 'wb') as f:
            f.write(cert_pem)
        
        # Salva password in file separato (in produzione: usare HSM o vault)
        with open(self.ca_dir / "ca_password.txt", 'w') as f:
            f.write(ca_password)
        os.chmod(self.ca_dir / "ca_password.txt", 0o600)
        
        print("   💾 Credenziali CA salvate in", self.ca_dir)
    
    def _load_existing_ca(self):
        """Carica CA esistente da filesystem"""
        
        # Carica password
        with open(self.ca_dir / "ca_password.txt", 'r') as f:
            ca_password = f.read().strip()
        
        # Carica chiavi
        self.ca_private_key, self.ca_public_key = self.key_manager.load_key_pair(
            str(self.ca_dir / "ca_private_key.pem"),
            str(self.ca_dir / "ca_public_key.pem"),
            ca_password
        )
        
        # Carica certificato
        with open(self.ca_dir / "ca_certificate.pem", 'rb') as f:
            cert_pem = f.read()
        self.ca_certificate = x509.load_pem_x509_certificate(cert_pem, self.backend)
        
        # Carica database certificati
        self._load_certificates_database()
    
    def issue_university_certificate(self, university_info: UniversityInfo, 
                                   university_public_key: rsa.RSAPublicKey,
                                   validity_years: int = 3) -> Tuple[x509.Certificate, str]:
        """
        Emette un certificato X.509v3 per un'università
        
        Args:
            university_info: Informazioni dell'università
            university_public_key: Chiave pubblica dell'università
            validity_years: Validità del certificato in anni
            
        Returns:
            Tupla (certificato, numero_seriale)
        """
        if not self.ca_certificate:
            raise RuntimeError("CA non inizializzata. Eseguire initialize_ca() prima.")
        
        try:
            print(f"🎓 Emissione certificato per: {university_info.name}")
            
            # Genera numero seriale univoco
            self.serial_counter += 1
            serial_number = self.serial_counter
            
            # Validità
            not_valid_before = datetime.datetime.utcnow()
            not_valid_after = not_valid_before + datetime.timedelta(days=365 * validity_years)
            
            # Subject dell'università
            university_subject = university_info.to_x509_name()
            
            # Builder certificato
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(university_subject)
            builder = builder.issuer_name(self.ca_certificate.subject)  # Issuer = CA
            builder = builder.public_key(university_public_key)
            builder = builder.serial_number(serial_number)
            builder = builder.not_valid_before(not_valid_before)
            builder = builder.not_valid_after(not_valid_after)
            
            # Estensioni per università (end entity)
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            
            builder = builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,     # Firma credenziali
                    content_commitment=True,    # Non-ripudio
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            
            # Extended Key Usage per università accademiche
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CODE_SIGNING,      # Firma credenziali
                    ExtendedKeyUsageOID.EMAIL_PROTECTION,  # Email sicure
                ]),
                critical=True,
            )
            
            # Subject Key Identifier
            builder = builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(university_public_key),
                critical=False,
            )
            
            # Authority Key Identifier
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_public_key),
                critical=False,
            )
            
            # Subject Alternative Names
            san_list = [
                x509.RFC822Name(university_info.email),  # Email
                x509.DNSName(university_info.website.replace("https://", "").replace("http://", "")),  # Website
            ]
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )
            
            # CRL Distribution Points (URL dove trovare lista revoche)
            crl_url = f"http://ca.academic-credentials.eu/crl/academic_ca.crl"
            builder = builder.add_extension(
                x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(crl_url)],
                        relative_name=None,
                        crl_issuer=None,
                        reasons=None,
                    )
                ]),
                critical=False,
            )
            
            # OCSP (Online Certificate Status Protocol)
            ocsp_url = f"http://ocsp.academic-credentials.eu"
            builder = builder.add_extension(
                x509.AuthorityInformationAccess([
                    x509.AccessDescription(
                        access_method=ExtensionOID.OCSP,
                        access_location=x509.UniformResourceIdentifier(ocsp_url),
                    ),
                ]),
                critical=False,
            )
            
            # Firma il certificato con la chiave privata della CA
            certificate = builder.sign(self.ca_private_key, hashes.SHA256(), self.backend)
            
            # Registra nel database
            cert_info = {
                'serial_number': str(serial_number),
                'university_name': university_info.name,
                'university_country': university_info.country,
                'erasmus_code': university_info.erasmus_code,
                'issued_date': not_valid_before.isoformat(),
                'expiry_date': not_valid_after.isoformat(),
                'status': 'active',
                'thumbprint_sha256': self.crypto_utils.sha256_hash(
                    certificate.public_bytes(serialization.Encoding.DER)
                )
            }
            
            self.issued_certificates[str(serial_number)] = cert_info
            
            # Salva certificato su filesystem
            cert_filename = f"university_{university_info.erasmus_code}_{serial_number}.pem"
            cert_path = self.issued_dir / cert_filename
            
            with open(cert_path, 'wb') as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
            
            # Salva database aggiornato
            self._save_certificates_database()
            
            print(f"✅ Certificato emesso con successo!")
            print(f"   Serial: {serial_number}")
            print(f"   Validità: {validity_years} anni")
            print(f"   File: {cert_filename}")
            
            return certificate, str(serial_number)
            
        except Exception as e:
            print(f"❌ Errore emissione certificato: {e}")
            raise
    
    def revoke_certificate(self, serial_number: str, reason_code: int, 
                          reason_description: str, revoked_by: str = "CA Administrator") -> bool:
        """
        Revoca un certificato
        
        Args:
            serial_number: Numero seriale del certificato
            reason_code: Codice motivo revoca (0-10)
            reason_description: Descrizione del motivo
            revoked_by: Chi ha effettuato la revoca
            
        Returns:
            True se revoca effettuata con successo
        """
        if serial_number not in self.issued_certificates:
            print(f"❌ Certificato {serial_number} non trovato")
            return False
        
        if serial_number in self.revoked_certificates:
            print(f"⚠️  Certificato {serial_number} già revocato")
            return False
        
        if reason_code not in self.REVOCATION_REASONS:
            print(f"❌ Codice motivo revoca non valido: {reason_code}")
            return False
        
        try:
            # Crea record di revoca
            revocation_info = CertificateRevocationInfo(
                certificate_serial=serial_number,
                revocation_time=datetime.datetime.utcnow(),
                reason_code=reason_code,
                reason_description=reason_description,
                revoked_by=revoked_by
            )
            
            # Aggiorna database
            self.revoked_certificates[serial_number] = revocation_info
            self.issued_certificates[serial_number]['status'] = 'revoked'
            self.issued_certificates[serial_number]['revocation_date'] = revocation_info.revocation_time.isoformat()
            
            # Salva database
            self._save_certificates_database()
            
            # Sposta certificato in directory revocati
            univ_info = self.issued_certificates[serial_number]
            old_filename = f"university_{univ_info['erasmus_code']}_{serial_number}.pem"
            old_path = self.issued_dir / old_filename
            new_path = self.revoked_dir / old_filename
            
            if old_path.exists():
                old_path.rename(new_path)
            
            print(f"✅ Certificato {serial_number} revocato con successo")
            print(f"   Motivo: {self.REVOCATION_REASONS[reason_code]} - {reason_description}")
            print(f"   Data: {revocation_info.revocation_time}")
            
            return True
            
        except Exception as e:
            print(f"❌ Errore revoca certificato: {e}")
            return False
    
    def verify_certificate(self, certificate: x509.Certificate) -> Dict[str, Any]:
        """
        Verifica un certificato emesso da questa CA
        
        Args:
            certificate: Certificato da verificare
            
        Returns:
            Dizionario con risultati verifica
        """
        result = {
            'valid': False,
            'serial_number': str(certificate.serial_number),
            'subject': certificate.subject.rfc4514_string(),
            'issuer': certificate.issuer.rfc4514_string(),
            'not_before': certificate.not_valid_before,
            'not_after': certificate.not_valid_after,
            'is_ca_issued': False,
            'is_revoked': False,
            'is_expired': False,
            'errors': []
        }
        
        try:
            # 1. Verifica che sia emesso da questa CA
            if certificate.issuer != self.ca_certificate.subject:
                result['errors'].append("Certificato non emesso da questa CA")
            else:
                result['is_ca_issued'] = True
            
            # 2. Verifica firma
            try:
                self.ca_public_key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    hashes.SHA256()
                )
            except Exception:
                result['errors'].append("Firma del certificato non valida")
            
            # 3. Verifica scadenza
            now = datetime.datetime.utcnow()
            if now < certificate.not_valid_before:
                result['errors'].append("Certificato non ancora valido")
            elif now > certificate.not_valid_after:
                result['errors'].append("Certificato scaduto")
                result['is_expired'] = True
            
            # 4. Verifica revoca
            serial_str = str(certificate.serial_number)
            if serial_str in self.revoked_certificates:
                result['is_revoked'] = True
                result['revocation_info'] = self.revoked_certificates[serial_str].to_dict()
                result['errors'].append("Certificato revocato")
            
            # 5. Risultato finale
            result['valid'] = len(result['errors']) == 0
            
            return result
            
        except Exception as e:
            result['errors'].append(f"Errore durante verifica: {e}")
            return result
    
    def generate_crl(self) -> x509.CertificateRevocationList:
        """
        Genera Certificate Revocation List (CRL)
        
        Returns:
            CRL con tutti i certificati revocati
        """
        if not self.ca_certificate:
            raise RuntimeError("CA non inizializzata")
        
        # Builder CRL
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.ca_certificate.subject)
        
        # Data ultima aggiornamento e prossimo aggiornamento
        last_update = datetime.datetime.utcnow()
        next_update = last_update + datetime.timedelta(days=7)  # CRL valida 7 giorni
        
        builder = builder.last_update(last_update)
        builder = builder.next_update(next_update)
        
        # Aggiunge certificati revocati
        for serial, revocation_info in self.revoked_certificates.items():
            revoked_cert = x509.RevokedCertificateBuilder()
            revoked_cert = revoked_cert.serial_number(int(serial))
            revoked_cert = revoked_cert.revocation_date(revocation_info.revocation_time)
            
            # Aggiunge estensione con motivo revoca
            revoked_cert = revoked_cert.add_extension(
                x509.CRLReason(x509.ReasonFlags(revocation_info.reason_code)),
                critical=False
            )
            
            builder = builder.add_revoked_certificate(revoked_cert.build(self.backend))
        
        # Firma la CRL
        crl = builder.sign(self.ca_private_key, hashes.SHA256(), self.backend)
        
        # Salva CRL su filesystem
        crl_path = self.ca_dir / "academic_ca.crl"
        with open(crl_path, 'wb') as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))
        
        print(f"✅ CRL generata con {len(self.revoked_certificates)} certificati revocati")
        print(f"   Valida fino a: {next_update}")
        
        return crl
    
    def _load_certificates_database(self):
        """Carica database certificati da file JSON"""
        db_path = self.ca_dir / "certificates_db.json"
        
        if db_path.exists():
            try:
                with open(db_path, 'r') as f:
                    data = json.load(f)
                
                self.issued_certificates = data.get('issued', {})
                
                # Carica certificati revocati
                revoked_data = data.get('revoked', {})
                self.revoked_certificates = {
                    serial: CertificateRevocationInfo.from_dict(info) 
                    for serial, info in revoked_data.items()
                }
                
                self.serial_counter = data.get('serial_counter', 1000)
                
                print(f"📚 Database caricato: {len(self.issued_certificates)} emessi, {len(self.revoked_certificates)} revocati")
                
            except Exception as e:
                print(f"⚠️  Errore caricamento database: {e}")
                print("   Inizializzo database vuoto")
                self._initialize_empty_database()
        else:
            self._initialize_empty_database()
    
    def _initialize_empty_database(self):
        """Inizializza database vuoto"""
        self.issued_certificates = {}
        self.revoked_certificates = {}
        self.serial_counter = 1000
        self._save_certificates_database()
    
    def _save_certificates_database(self):
        """Salva database certificati su file JSON"""
        db_path = self.ca_dir / "certificates_db.json"
        
        # Converte certificati revocati in formato serializzabile
        revoked_data = {
            serial: info.to_dict() 
            for serial, info in self.revoked_certificates.items()
        }
        
        data = {
            'issued': self.issued_certificates,
            'revoked': revoked_data,
            'serial_counter': self.serial_counter,
            'last_updated': datetime.datetime.utcnow().isoformat()
        }
        
        with open(db_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def _print_ca_info(self):
        """Stampa informazioni della CA"""
        if not self.ca_certificate:
            return
        
        print("\n" + "=" * 60)
        print("📋 INFORMAZIONI CERTIFICATE AUTHORITY")
        print("=" * 60)
        print(f"Nome: {self.ca_name}")
        print(f"Subject: {self.ca_certificate.subject.rfc4514_string()}")
        print(f"Serial: {self.ca_certificate.serial_number}")
        print(f"Validità: {self.ca_certificate.not_valid_before} → {self.ca_certificate.not_valid_after}")
        print(f"Key Size: {self.key_size} bit")
        print(f"Algoritmo: RSA-SHA256")
        print(f"Thumbprint: {self.crypto_utils.sha256_hash(self.ca_certificate.public_bytes(serialization.Encoding.DER))[:16]}...")
        print("=" * 60)
    
    def get_ca_info(self) -> Dict[str, Any]:
        """
        Ottiene informazioni complete della CA
        
        Returns:
            Dizionario con informazioni CA
        """
        if not self.ca_certificate:
            return {"error": "CA non inizializzata"}
        
        return {
            "ca_name": self.ca_name,
            "subject": self.ca_certificate.subject.rfc4514_string(),
            "serial_number": str(self.ca_certificate.serial_number),
            "not_valid_before": self.ca_certificate.not_valid_before.isoformat(),
            "not_valid_after": self.ca_certificate.not_valid_after.isoformat(),
            "key_size": self.key_size,
            "algorithm": "RSA-SHA256",
            "thumbprint_sha256": self.crypto_utils.sha256_hash(
                self.ca_certificate.public_bytes(serialization.Encoding.DER)
            ),
            "certificates_issued": len(self.issued_certificates),
            "certificates_revoked": len(self.revoked_certificates),
            "next_serial": self.serial_counter + 1
        }
    
    def list_issued_certificates(self) -> List[Dict[str, Any]]:
        """
        Lista tutti i certificati emessi
        
        Returns:
            Lista con informazioni certificati
        """
        return list(self.issued_certificates.values())
    
    def list_revoked_certificates(self) -> List[Dict[str, Any]]:
        """
        Lista tutti i certificati revocati
        
        Returns:
            Lista con informazioni revoche
        """
        return [info.to_dict() for info in self.revoked_certificates.values()]


# =============================================================================
# 6. FUNZIONI DI UTILITÀ PER UNIVERSITÀ
# =============================================================================

def create_sample_universities() -> List[UniversityInfo]:
    """Crea università di esempio per testing"""
    
    universities = [
        UniversityInfo(
            name="Université de Rennes",
            country="FR",
            erasmus_code="F RENNES01",
            legal_name="Université de Rennes",
            tax_id="FR12345678901",
            address="2 Rue du Thabor",
            city="Rennes", 
            state_province="Bretagne",
            postal_code="35000",
            email="international@univ-rennes1.fr",
            website="https://www.univ-rennes1.fr",
            accreditation_body="Ministère de l'Enseignement Supérieur",
            accreditation_number="UAI_0351721M"
        ),
        
        UniversityInfo(
            name="Università degli Studi di Salerno",
            country="IT", 
            erasmus_code="I SALERNO01",
            legal_name="Università degli Studi di Salerno",
            tax_id="IT80008810652",
            address="Via Giovanni Paolo II, 132",
            city="Fisciano",
            state_province="Campania", 
            postal_code="84084",
            email="international@unisa.it",
            website="https://www.unisa.it",
            accreditation_body="MIUR - Ministero dell'Istruzione",
            accreditation_number="COD_MIUR_057"
        ),
        
        UniversityInfo(
            name="Technische Universität München",
            country="DE",
            erasmus_code="D MUNCHEN02",
            legal_name="Technische Universität München",
            tax_id="DE129518138",
            address="Arcisstraße 21",
            city="München",
            state_province="Bayern",
            postal_code="80333", 
            email="international@tum.de",
            website="https://www.tum.de",
            accreditation_body="Bayerisches Staatsministerium",
            accreditation_number="BY_TUM_001"
        )
    ]
    
    return universities


# =============================================================================
# 7. DEMO E TESTING
# =============================================================================

def demo_certificate_authority():
    """Demo completa della Certificate Authority"""
    
    print("🏛️" * 30)
    print("DEMO CERTIFICATE AUTHORITY")
    print("Sistema Credenziali Accademiche")
    print("🏛️" * 30)
    
    try:
        # 1. Inizializza CA
        print("\n1️⃣ INIZIALIZZAZIONE CERTIFICATE AUTHORITY")
        ca = AcademicCertificateAuthority(
            ca_name="European Academic Credentials CA",
            key_size=4096,
            validity_years=10
        )
        
        success = ca.initialize_ca(force_recreate=False)
        if not success:
            print("❌ Fallimento inizializzazione CA")
            return
        
        # 2. Crea università di esempio
        print("\n2️⃣ CREAZIONE UNIVERSITÀ DI ESEMPIO")
        universities = create_sample_universities()
        
        for i, univ in enumerate(universities):
            print(f"   {i+1}. {univ.name} ({univ.erasmus_code})")
        
        # 3. Genera certificati per le università
        print("\n3️⃣ EMISSIONE CERTIFICATI UNIVERSITÀ")
        university_certs = {}
        key_manager = RSAKeyManager(2048)
        
        for univ in universities:
            print(f"\n   📜 Certificazione: {univ.name}")
            
            # Genera chiavi per l'università
            univ_private, univ_public = key_manager.generate_key_pair()
            
            # Emette certificato
            certificate, serial = ca.issue_university_certificate(
                univ, univ_public, validity_years=3
            )
            
            university_certs[univ.erasmus_code] = {
                'certificate': certificate,
                'serial': serial,
                'private_key': univ_private,
                'public_key': univ_public,
                'university_info': univ
            }
        
        # 4. Verifica certificati
        print("\n4️⃣ VERIFICA CERTIFICATI")
        for code, cert_data in university_certs.items():
            print(f"\n   🔍 Verifica: {cert_data['university_info'].name}")
            
            verification = ca.verify_certificate(cert_data['certificate'])
            
            if verification['valid']:
                print(f"   ✅ Certificato VALIDO (Serial: {verification['serial_number']})")
            else:
                print(f"   ❌ Certificato NON VALIDO")
                for error in verification['errors']:
                    print(f"      - {error}")
        
        # 5. Simulazione revoca
        print("\n5️⃣ SIMULAZIONE REVOCA CERTIFICATO")
        # Revoca il certificato dell'Università di Rennes per test
        rennes_serial = university_certs['F RENNES01']['serial']
        
        revoke_success = ca.revoke_certificate(
            rennes_serial,
            reason_code=3,  # affiliationChanged
            reason_description="Test revoca per dimostrazione sistema",
            revoked_by="Demo Administrator"
        )
        
        if revoke_success:
            # Ri-verifica dopo revoca
            rennes_cert = university_certs['F RENNES01']['certificate']
            verification_after = ca.verify_certificate(rennes_cert)
            
            print(f"   📝 Verifica post-revoca: {'❌ REVOCATO' if verification_after['is_revoked'] else '✅ VALIDO'}")
        
        # 6. Generazione CRL
        print("\n6️⃣ GENERAZIONE CERTIFICATE REVOCATION LIST")
        crl = ca.generate_crl()
        print(f"   📋 CRL generata con {len(ca.revoked_certificates)} certificati revocati")
        
        # 7. Statistiche finali
        print("\n7️⃣ STATISTICHE FINALI")
        ca_info = ca.get_ca_info()
        print(f"   📊 Certificati emessi: {ca_info['certificates_issued']}")
        print(f"   📊 Certificati revocati: {ca_info['certificates_revoked']}")
        print(f"   📊 Prossimo serial: {ca_info['next_serial']}")
        
        issued_list = ca.list_issued_certificates()
        print(f"   📋 Certificati attivi: {len([c for c in issued_list if c['status'] == 'active'])}")
        
        print("\n" + "✅" * 30)
        print("DEMO COMPLETATA CON SUCCESSO!")
        print("✅" * 30)
        
        print(f"\n📁 File generati in:")
        print(f"   CA: ./certificates/ca/")
        print(f"   Certificati: ./certificates/issued/")
        print(f"   Revocati: ./certificates/revoked/")
        
        return ca, university_certs
        
    except Exception as e:
        print(f"\n❌ Errore durante demo: {e}")
        import traceback
        traceback.print_exc()
        return None, None


# =============================================================================
# 8. MAIN - PUNTO DI INGRESSO
# =============================================================================

if __name__ == "__main__":
    print("🔐" * 40)
    print("FASE 2: GESTIONE CERTIFICATI X.509")
    print("Certificate Authority per Credenziali Accademiche")
    print("🔐" * 40)
    
    # Esegui demo completa
    ca_instance, university_certificates = demo_certificate_authority()
    
    if ca_instance:
        print("\n🎉 FASE 2 COMPLETATA CON SUCCESSO!")
        print("\nComponenti implementati:")
        print("✅ Certificate Authority con certificato root")
        print("✅ Emissione certificati X.509v3 per università")
        print("✅ Gestione revoche e CRL")
        print("✅ Verifica certificati e catena di fiducia")
        print("✅ Database persistente certificati")
        print("✅ Estensioni X.509 per scopo accademico")
        
        print(f"\n🚀 Pronto per la Fase 3: Struttura Credenziali Accademiche!")
    else:
        print("\n❌ Fase 2 fallita - verificare l'implementazione")