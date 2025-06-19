# =============================================================================
# FASE 2: GESTIONE CERTIFICATI X.509 - CERTIFICATE MANAGER
# File: pki/certificate_manager.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import json
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass

# Cryptography imports
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Import crypto foundations
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from crypto.foundations import CryptoUtils
except ImportError:
    print("⚠️  Assicurati che crypto/foundations.py sia presente nel progetto")
    raise


# =============================================================================
# 1. STRUTTURE DATI PER GESTIONE CERTIFICATI
# =============================================================================

@dataclass
class CertificateInfo:
    """Informazioni estratte da un certificato X.509"""
    subject: str                    # Subject DN
    issuer: str                     # Issuer DN
    serial_number: str              # Numero seriale
    not_valid_before: datetime.datetime  # Data inizio validità
    not_valid_after: datetime.datetime   # Data fine validità
    thumbprint_sha256: str          # Thumbprint SHA-256
    key_usage: List[str]           # Key usage extensions
    extended_key_usage: List[str]  # Extended key usage
    subject_alt_names: List[str]   # Subject alternative names
    is_ca: bool                    # È un certificato CA
    key_size: int                  # Dimensione chiave
    signature_algorithm: str       # Algoritmo firma
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario per serializzazione"""
        return {
            'subject': self.subject,
            'issuer': self.issuer,
            'serial_number': self.serial_number,
            'not_valid_before': self.not_valid_before.isoformat(),
            'not_valid_after': self.not_valid_after.isoformat(),
            'thumbprint_sha256': self.thumbprint_sha256,
            'key_usage': self.key_usage,
            'extended_key_usage': self.extended_key_usage,
            'subject_alt_names': self.subject_alt_names,
            'is_ca': self.is_ca,
            'key_size': self.key_size,
            'signature_algorithm': self.signature_algorithm
        }


@dataclass
class CertificateChain:
    """Rappresenta una catena di certificati"""
    end_entity: x509.Certificate           # Certificato end-entity
    intermediates: List[x509.Certificate]  # Certificati intermedi
    root_ca: x509.Certificate             # Certificato root CA
    
    def get_full_chain(self) -> List[x509.Certificate]:
        """Ottiene la catena completa ordinata"""
        return [self.end_entity] + self.intermediates + [self.root_ca]
    
    def to_pem_bundle(self) -> str:
        """Converte la catena in bundle PEM"""
        pem_parts = []
        for cert in self.get_full_chain():
            pem_parts.append(cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'))
        return '\n'.join(pem_parts)


# =============================================================================
# 2. CERTIFICATE MANAGER PRINCIPALE
# =============================================================================

class CertificateManager:
    """Gestisce parsing, validazione e operazioni sui certificati X.509"""
    
    def __init__(self):
        """Inizializza il Certificate Manager"""
        self.backend = default_backend()
        self.crypto_utils = CryptoUtils()
        
        # Cache certificati per performance
        self.certificate_cache: Dict[str, x509.Certificate] = {}
        self.chain_cache: Dict[str, CertificateChain] = {}
        
        print("📋 Certificate Manager inizializzato")
    
    def load_certificate_from_file(self, file_path: str) -> x509.Certificate:
        """
        Carica un certificato da file PEM o DER
        
        Args:
            file_path: Percorso del file certificato
            
        Returns:
            Certificato X.509
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File certificato non trovato: {file_path}")
        
        # Controlla cache
        cache_key = str(file_path.absolute())
        if cache_key in self.certificate_cache:
            print(f"📄 Certificato caricato da cache: {file_path.name}")
            return self.certificate_cache[cache_key]
        
        try:
            with open(file_path, 'rb') as f:
                cert_data = f.read()
            
            # Prova prima PEM, poi DER
            try:
                certificate = x509.load_pem_x509_certificate(cert_data, self.backend)
                encoding = "PEM"
            except ValueError:
                try:
                    certificate = x509.load_der_x509_certificate(cert_data, self.backend)
                    encoding = "DER"
                except ValueError:
                    raise ValueError("Formato certificato non riconosciuto (né PEM né DER)")
            
            # Salva in cache
            self.certificate_cache[cache_key] = certificate
            
            print(f"✅ Certificato caricato: {file_path.name} ({encoding})")
            return certificate
            
        except Exception as e:
            raise RuntimeError(f"Errore caricamento certificato {file_path}: {e}")
    
    def load_certificate_from_bytes(self, cert_data: bytes, encoding: str = "PEM") -> x509.Certificate:
        """
        Carica un certificato da dati binari
        
        Args:
            cert_data: Dati del certificato
            encoding: Encoding ("PEM" o "DER")
            
        Returns:
            Certificato X.509
        """
        try:
            if encoding.upper() == "PEM":
                certificate = x509.load_pem_x509_certificate(cert_data, self.backend)
            elif encoding.upper() == "DER":
                certificate = x509.load_der_x509_certificate(cert_data, self.backend)
            else:
                raise ValueError("Encoding deve essere 'PEM' o 'DER'")
            
            print(f"✅ Certificato caricato da bytes ({encoding})")
            return certificate
            
        except Exception as e:
            raise RuntimeError(f"Errore caricamento certificato da bytes: {e}")
    
    def parse_certificate(self, certificate: x509.Certificate) -> CertificateInfo:
        """
        Estrae informazioni dettagliate da un certificato
        
        Args:
            certificate: Certificato X.509
            
        Returns:
            Informazioni del certificato
        """
        try:
            # Informazioni di base
            subject = certificate.subject.rfc4514_string()
            issuer = certificate.issuer.rfc4514_string()
            serial_number = str(certificate.serial_number)
            
            # Calcola thumbprint
            cert_der = certificate.public_bytes(serialization.Encoding.DER)
            thumbprint = self.crypto_utils.sha256_hash(cert_der)
            
            # Key usage
            key_usage_list = []
            try:
                key_usage_ext = certificate.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.KEY_USAGE
                ).value
                
                if key_usage_ext.digital_signature:
                    key_usage_list.append("digital_signature")
                if key_usage_ext.content_commitment:
                    key_usage_list.append("content_commitment") 
                if key_usage_ext.key_encipherment:
                    key_usage_list.append("key_encipherment")
                if key_usage_ext.data_encipherment:
                    key_usage_list.append("data_encipherment")
                if key_usage_ext.key_agreement:
                    key_usage_list.append("key_agreement")
                if key_usage_ext.key_cert_sign:
                    key_usage_list.append("key_cert_sign")
                if key_usage_ext.crl_sign:
                    key_usage_list.append("crl_sign")
                    
            except x509.ExtensionNotFound:
                key_usage_list = ["not_specified"]
            
            # Extended key usage
            ext_key_usage_list = []
            try:
                ext_key_usage_ext = certificate.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
                ).value
                
                for eku in ext_key_usage_ext:
                    if eku == ExtendedKeyUsageOID.CODE_SIGNING:
                        ext_key_usage_list.append("code_signing")
                    elif eku == ExtendedKeyUsageOID.EMAIL_PROTECTION:
                        ext_key_usage_list.append("email_protection")
                    elif eku == ExtendedKeyUsageOID.SERVER_AUTH:
                        ext_key_usage_list.append("server_auth")
                    elif eku == ExtendedKeyUsageOID.CLIENT_AUTH:
                        ext_key_usage_list.append("client_auth")
                    else:
                        ext_key_usage_list.append(str(eku))
                        
            except x509.ExtensionNotFound:
                ext_key_usage_list = []
            
            # Subject Alternative Names
            san_list = []
            try:
                san_ext = certificate.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                ).value
                
                for san in san_ext:
                    if isinstance(san, x509.DNSName):
                        san_list.append(f"DNS:{san.value}")
                    elif isinstance(san, x509.RFC822Name):
                        san_list.append(f"EMAIL:{san.value}")
                    elif isinstance(san, x509.UniformResourceIdentifier):
                        san_list.append(f"URI:{san.value}")
                    else:
                        san_list.append(f"OTHER:{str(san)}")
                        
            except x509.ExtensionNotFound:
                san_list = []
            
            # Basic Constraints (CA)
            is_ca = False
            try:
                basic_constraints = certificate.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                ).value
                is_ca = basic_constraints.ca
            except x509.ExtensionNotFound:
                pass
            
            # Dimensione chiave
            public_key = certificate.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                key_size = public_key.key_size
            else:
                key_size = 0  # Algoritmo non RSA
            
            # Algoritmo firma
            signature_algorithm = certificate.signature_algorithm_oid._name
            
            cert_info = CertificateInfo(
                subject=subject,
                issuer=issuer,
                serial_number=serial_number,
                not_valid_before=certificate.not_valid_before,
                not_valid_after=certificate.not_valid_after,
                thumbprint_sha256=thumbprint,
                key_usage=key_usage_list,
                extended_key_usage=ext_key_usage_list,
                subject_alt_names=san_list,
                is_ca=is_ca,
                key_size=key_size,
                signature_algorithm=signature_algorithm
            )
            
            print(f"📋 Certificato analizzato: {self._get_common_name(certificate)}")
            return cert_info
            
        except Exception as e:
            raise RuntimeError(f"Errore parsing certificato: {e}")
    
    def validate_certificate_chain(self, certificates: List[x509.Certificate], 
                                 trusted_ca_cert: x509.Certificate) -> Dict[str, Any]:
        """
        Valida una catena di certificati
        
        Args:
            certificates: Lista certificati (end-entity prima, CA alla fine)
            trusted_ca_cert: Certificato CA di fiducia
            
        Returns:
            Risultato validazione
        """
        result = {
            'valid': False,
            'chain_length': len(certificates),
            'end_entity_subject': '',
            'trusted_ca_subject': '',
            'errors': [],
            'warnings': []
        }
        
        try:
            if not certificates:
                result['errors'].append("Nessun certificato nella catena")
                return result
            
            end_entity = certificates[0]
            result['end_entity_subject'] = end_entity.subject.rfc4514_string()
            result['trusted_ca_subject'] = trusted_ca_cert.subject.rfc4514_string()
            
            # 1. Verifica che l'ultimo certificato sia la CA di fiducia
            root_cert = certificates[-1] if len(certificates) > 1 else trusted_ca_cert
            
            if root_cert.subject != trusted_ca_cert.subject:
                result['errors'].append("Root CA nella catena non corrisponde alla CA di fiducia")
                # Prova comunque con la CA di fiducia
                chain_to_verify = certificates + [trusted_ca_cert]
            else:
                chain_to_verify = certificates
            
            # 2. Verifica ogni link nella catena
            for i in range(len(chain_to_verify) - 1):
                current_cert = chain_to_verify[i]
                issuer_cert = chain_to_verify[i + 1]
                
                # Verifica che l'issuer del certificato corrente sia il subject del successivo
                if current_cert.issuer != issuer_cert.subject:
                    result['errors'].append(f"Interruzione catena al livello {i}: issuer non corrisponde")
                    continue
                
                # Verifica firma
                try:
                    issuer_public_key = issuer_cert.public_key()
                    issuer_public_key.verify(
                        current_cert.signature,
                        current_cert.tbs_certificate_bytes,
                        current_cert.signature_hash_algorithm
                    )
                    print(f"   ✅ Firma valida: {self._get_common_name(current_cert)}")
                    
                except InvalidSignature:
                    result['errors'].append(f"Firma non valida al livello {i}")
                except Exception as e:
                    result['errors'].append(f"Errore verifica firma livello {i}: {e}")
            
            # 3. Verifica validità temporale
            now = datetime.datetime.utcnow()
            for i, cert in enumerate(chain_to_verify):
                if now < cert.not_valid_before:
                    result['errors'].append(f"Certificato {i} non ancora valido")
                elif now > cert.not_valid_after:
                    result['errors'].append(f"Certificato {i} scaduto")
            
            # 4. Verifica Basic Constraints per CA intermedie
            for i in range(1, len(chain_to_verify)):  # Salta end-entity
                cert = chain_to_verify[i]
                try:
                    basic_constraints = cert.extensions.get_extension_for_oid(
                        x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                    ).value
                    
                    if not basic_constraints.ca:
                        result['errors'].append(f"Certificato {i} non è marcato come CA")
                        
                except x509.ExtensionNotFound:
                    result['warnings'].append(f"Certificato {i} manca Basic Constraints")
            
            # 5. Risultato finale
            result['valid'] = len(result['errors']) == 0
            
            if result['valid']:
                print(f"✅ Catena certificati VALIDA ({len(chain_to_verify)} livelli)")
            else:
                print(f"❌ Catena certificati NON VALIDA ({len(result['errors'])} errori)")
            
            return result
            
        except Exception as e:
            result['errors'].append(f"Errore durante validazione: {e}")
            return result
    
    def build_certificate_chain(self, end_entity_cert: x509.Certificate,
                               intermediate_certs: List[x509.Certificate],
                               root_ca_cert: x509.Certificate) -> CertificateChain:
        """
        Costruisce una catena di certificati ordinata
        
        Args:
            end_entity_cert: Certificato end-entity
            intermediate_certs: Lista certificati intermedi
            root_ca_cert: Certificato root CA
            
        Returns:
            Catena di certificati ordinata
        """
        try:
            # Ordina i certificati intermedi
            ordered_intermediates = self._order_intermediate_certificates(
                end_entity_cert, intermediate_certs, root_ca_cert
            )
            
            chain = CertificateChain(
                end_entity=end_entity_cert,
                intermediates=ordered_intermediates,
                root_ca=root_ca_cert
            )
            
            print(f"🔗 Catena costruita: 1 end-entity + {len(ordered_intermediates)} intermedi + 1 root")
            return chain
            
        except Exception as e:
            raise RuntimeError(f"Errore costruzione catena: {e}")
    
    def extract_public_key(self, certificate: x509.Certificate) -> rsa.RSAPublicKey:
        """
        Estrae la chiave pubblica da un certificato
        
        Args:
            certificate: Certificato X.509
            
        Returns:
            Chiave pubblica RSA
        """
        try:
            public_key = certificate.public_key()
            
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise TypeError("Il certificato non contiene una chiave RSA")
            
            print(f"🔑 Chiave pubblica estratta: {public_key.key_size} bit")
            return public_key
            
        except Exception as e:
            raise RuntimeError(f"Errore estrazione chiave pubblica: {e}")
    
    def verify_certificate_signature(self, certificate: x509.Certificate,
                                   issuer_public_key: rsa.RSAPublicKey) -> bool:
        """
        Verifica la firma di un certificato
        
        Args:
            certificate: Certificato da verificare
            issuer_public_key: Chiave pubblica dell'issuer
            
        Returns:
            True se la firma è valida
        """
        try:
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                certificate.signature_hash_algorithm
            )
            
            print(f"✅ Firma certificato verificata: {self._get_common_name(certificate)}")
            return True
            
        except InvalidSignature:
            print(f"❌ Firma certificato non valida: {self._get_common_name(certificate)}")
            return False
        except Exception as e:
            print(f"❌ Errore verifica firma: {e}")
            return False
    
    def check_certificate_expiry(self, certificate: x509.Certificate,
                               warning_days: int = 30) -> Dict[str, Any]:
        """
        Controlla la scadenza di un certificato
        
        Args:
            certificate: Certificato da controllare
            warning_days: Giorni prima della scadenza per warning
            
        Returns:
            Informazioni scadenza
        """
        now = datetime.datetime.utcnow()
        
        result = {
            'is_valid': False,
            'is_expired': False,
            'expires_soon': False,
            'not_valid_before': certificate.not_valid_before,
            'not_valid_after': certificate.not_valid_after,
            'days_until_expiry': 0,
            'status': ''
        }
        
        try:
            # Calcola giorni alla scadenza
            days_until_expiry = (certificate.not_valid_after - now).days
            result['days_until_expiry'] = days_until_expiry
            
            if now < certificate.not_valid_before:
                result['status'] = 'not_yet_valid'
            elif now > certificate.not_valid_after:
                result['status'] = 'expired'
                result['is_expired'] = True
            elif days_until_expiry <= warning_days:
                result['status'] = 'expires_soon'
                result['is_valid'] = True
                result['expires_soon'] = True
            else:
                result['status'] = 'valid'
                result['is_valid'] = True
            
            cn = self._get_common_name(certificate)
            
            if result['is_expired']:
                print(f"⚠️  Certificato SCADUTO: {cn} (scaduto {abs(days_until_expiry)} giorni fa)")
            elif result['expires_soon']:
                print(f"⚠️  Certificato in SCADENZA: {cn} (scade in {days_until_expiry} giorni)")
            else:
                print(f"✅ Certificato VALIDO: {cn} (scade in {days_until_expiry} giorni)")
            
            return result
            
        except Exception as e:
            result['status'] = f'error: {e}'
            return result
    
    def save_certificate_to_file(self, certificate: x509.Certificate, 
                                file_path: str, encoding: str = "PEM") -> bool:
        """
        Salva un certificato su file
        
        Args:
            certificate: Certificato da salvare
            file_path: Percorso file di destinazione
            encoding: Encoding ("PEM" o "DER")
            
        Returns:
            True se salvato con successo
        """
        try:
            file_path = Path(file_path)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            if encoding.upper() == "PEM":
                cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
            elif encoding.upper() == "DER":
                cert_bytes = certificate.public_bytes(serialization.Encoding.DER)
            else:
                raise ValueError("Encoding deve essere 'PEM' o 'DER'")
            
            with open(file_path, 'wb') as f:
                f.write(cert_bytes)
            
            print(f"💾 Certificato salvato: {file_path} ({encoding})")
            return True
            
        except Exception as e:
            print(f"❌ Errore salvataggio certificato: {e}")
            return False
    
    def get_certificate_summary(self, certificate: x509.Certificate) -> Dict[str, Any]:
        """
        Ottiene un riassunto del certificato
        
        Args:
            certificate: Certificato X.509
            
        Returns:
            Riassunto del certificato
        """
        try:
            cert_info = self.parse_certificate(certificate)
            expiry_info = self.check_certificate_expiry(certificate)
            
            summary = {
                'common_name': self._get_common_name(certificate),
                'organization': self._get_organization(certificate),
                'country': self._get_country(certificate),
                'serial_number': cert_info.serial_number,
                'thumbprint': cert_info.thumbprint_sha256[:16] + "...",
                'key_size': cert_info.key_size,
                'signature_algorithm': cert_info.signature_algorithm,
                'is_ca': cert_info.is_ca,
                'validity_status': expiry_info['status'],
                'days_until_expiry': expiry_info['days_until_expiry'],
                'key_usage': cert_info.key_usage,
                'extended_key_usage': cert_info.extended_key_usage
            }
            
            return summary
            
        except Exception as e:
            return {'error': f'Errore creazione riassunto: {e}'}
    
    def _order_intermediate_certificates(self, end_entity: x509.Certificate,
                                       intermediates: List[x509.Certificate],
                                       root_ca: x509.Certificate) -> List[x509.Certificate]:
        """Ordina i certificati intermedi per costruire la catena corretta"""
        if not intermediates:
            return []
        
        ordered = []
        remaining = intermediates.copy()
        current_issuer = end_entity.issuer
        
        while remaining and current_issuer != root_ca.subject:
            found = False
            
            for cert in remaining:
                if cert.subject == current_issuer:
                    ordered.append(cert)
                    remaining.remove(cert)
                    current_issuer = cert.issuer
                    found = True
                    break
            
            if not found:
                break  # Catena interrotta
        
        return ordered
    
    def _get_common_name(self, certificate: x509.Certificate) -> str:
        """Estrae il Common Name dal certificato"""
        try:
            for attribute in certificate.subject:
                if attribute.oid == NameOID.COMMON_NAME:
                    return attribute.value
            return "N/A"
        except:
            return "N/A"
    
    def _get_organization(self, certificate: x509.Certificate) -> str:
        """Estrae l'Organization dal certificato"""
        try:
            for attribute in certificate.subject:
                if attribute.oid == NameOID.ORGANIZATION_NAME:
                    return attribute.value
            return "N/A"
        except:
            return "N/A"
    
    def _get_country(self, certificate: x509.Certificate) -> str:
        """Estrae il Country dal certificato"""
        try:
            for attribute in certificate.subject:
                if attribute.oid == NameOID.COUNTRY_NAME:
                    return attribute.value
            return "N/A"
        except:
            return "N/A"


# =============================================================================
# 3. UTILITIES PER GESTIONE CERTIFICATI
# =============================================================================

class CertificateStore:
    """Store per gestire collezioni di certificati"""
    
    def __init__(self, store_directory: str = "./certificates/store"):
        """
        Inizializza il certificate store
        
        Args:
            store_directory: Directory per archiviare i certificati
        """
        self.store_dir = Path(store_directory)
        self.store_dir.mkdir(parents=True, exist_ok=True)
        
        self.certificates: Dict[str, x509.Certificate] = {}
        self.certificate_info: Dict[str, CertificateInfo] = {}
        
        self.cert_manager = CertificateManager()
        
        print(f"🗃️  Certificate Store inizializzato: {self.store_dir}")
    
    def add_certificate(self, certificate: x509.Certificate, 
                       alias: str = None) -> str:
        """
        Aggiunge un certificato allo store
        
        Args:
            certificate: Certificato da aggiungere
            alias: Alias per il certificato (opzionale)
            
        Returns:
            Alias assegnato al certificato
        """
        try:
            # Genera alias se non fornito
            if not alias:
                cn = self.cert_manager._get_common_name(certificate)
                serial = str(certificate.serial_number)
                alias = f"{cn}_{serial}"
            
            # Rimuovi caratteri non validi dall'alias
            alias = "".join(c for c in alias if c.isalnum() or c in "._-")
            
            # Aggiungi allo store
            self.certificates[alias] = certificate
            self.certificate_info[alias] = self.cert_manager.parse_certificate(certificate)
            
            # Salva su filesystem
            cert_file = self.store_dir / f"{alias}.pem"
            self.cert_manager.save_certificate_to_file(certificate, str(cert_file))
            
            print(f"📁 Certificato aggiunto allo store: {alias}")
            return alias
            
        except Exception as e:
            print(f"❌ Errore aggiunta certificato: {e}")
            raise
    
    def get_certificate(self, alias: str) -> Optional[x509.Certificate]:
        """Ottiene un certificato per alias"""
        return self.certificates.get(alias)
    
    def list_certificates(self) -> List[Dict[str, Any]]:
        """Lista tutti i certificati nello store"""
        result = []
        
        for alias, cert in self.certificates.items():
            summary = self.cert_manager.get_certificate_summary(cert)
            summary['alias'] = alias
            result.append(summary)
        
        return result
    
    def remove_certificate(self, alias: str) -> bool:
        """Rimuove un certificato dallo store"""
        try:
            if alias in self.certificates:
                del self.certificates[alias]
                del self.certificate_info[alias]
                
                cert_file = self.store_dir / f"{alias}.pem"
                if cert_file.exists():
                    cert_file.unlink()
                
                print(f"🗑️  Certificato rimosso: {alias}")
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ Errore rimozione certificato: {e}")
            return False
    
    def load_certificates_from_directory(self, directory: str) -> int:
        """
        Carica tutti i certificati da una directory
        
        Args:
            directory: Directory contenente certificati PEM
            
        Returns:
            Numero di certificati caricati
        """
        directory = Path(directory)
        loaded_count = 0
        
        if not directory.exists():
            print(f"⚠️  Directory non trovata: {directory}")
            return 0
        
        for cert_file in directory.glob("*.pem"):
            try:
                certificate = self.cert_manager.load_certificate_from_file(str(cert_file))
                alias = cert_file.stem
                self.add_certificate(certificate, alias)
                loaded_count += 1
                
            except Exception as e:
                print(f"⚠️  Errore caricamento {cert_file}: {e}")
        
        print(f"📚 Caricati {loaded_count} certificati da {directory}")
        return loaded_count


# =============================================================================
# 4. DEMO E TESTING
# =============================================================================

def demo_certificate_manager():
    """Demo del Certificate Manager"""
    
    print("📋" * 30)
    print("DEMO CERTIFICATE MANAGER")
    print("Gestione Certificati X.509")
    print("📋" * 30)
    
    try:
        # 1. Inizializza manager
        print("\n1️⃣ INIZIALIZZAZIONE CERTIFICATE MANAGER")
        cert_manager = CertificateManager()
        
        # 2. Carica certificati dalla CA (se esistenti)
        print("\n2️⃣ CARICAMENTO CERTIFICATI ESISTENTI")
        ca_dir = Path("./certificates/ca")
        issued_dir = Path("./certificates/issued")
        
        certificates_loaded = []
        
        if ca_dir.exists():
            # Carica certificato CA
            ca_cert_path = ca_dir / "ca_certificate.pem"
            if ca_cert_path.exists():
                ca_cert = cert_manager.load_certificate_from_file(str(ca_cert_path))
                certificates_loaded.append(("CA Certificate", ca_cert))
                print(f"   ✅ Certificato CA caricato")
        
        if issued_dir.exists():
            # Carica certificati università
            for cert_file in issued_dir.glob("*.pem"):
                try:
                    cert = cert_manager.load_certificate_from_file(str(cert_file))
                    certificates_loaded.append((cert_file.stem, cert))
                except Exception as e:
                    print(f"   ⚠️  Errore caricamento {cert_file}: {e}")
        
        if not certificates_loaded:
            print("   ⚠️  Nessun certificato trovato. Esegui prima certificate_authority.py")
            return
        
        # 3. Analisi certificati
        print(f"\n3️⃣ ANALISI CERTIFICATI ({len(certificates_loaded)} trovati)")
        
        for name, cert in certificates_loaded:
            print(f"\n   📜 {name}")
            
            # Parse del certificato
            cert_info = cert_manager.parse_certificate(cert)
            
            print(f"      Subject: {cert_info.subject}")
            print(f"      Serial: {cert_info.serial_number}")
            print(f"      Key Size: {cert_info.key_size} bit")
            print(f"      Is CA: {cert_info.is_ca}")
            print(f"      Thumbprint: {cert_info.thumbprint_sha256[:16]}...")
            
            # Controllo scadenza
            expiry_info = cert_manager.check_certificate_expiry(cert)
            print(f"      Status: {expiry_info['status']} ({expiry_info['days_until_expiry']} giorni)")
        
        # 4. Validazione catena (se abbiamo CA + certificati università)
        print("\n4️⃣ VALIDAZIONE CATENA CERTIFICATI")
        
        ca_cert = None
        university_certs = []
        
        for name, cert in certificates_loaded:
            cert_info = cert_manager.parse_certificate(cert)
            if cert_info.is_ca:
                ca_cert = cert
            else:
                university_certs.append(cert)
        
        if ca_cert and university_certs:
            for univ_cert in university_certs[:2]:  # Testa primi 2
                chain = [univ_cert, ca_cert]  # Catena semplice
                
                validation_result = cert_manager.validate_certificate_chain(chain, ca_cert)
                
                cn = cert_manager._get_common_name(univ_cert)
                if validation_result['valid']:
                    print(f"   ✅ Catena VALIDA per: {cn}")
                else:
                    print(f"   ❌ Catena NON VALIDA per: {cn}")
                    for error in validation_result['errors']:
                        print(f"      - {error}")
        
        # 5. Test Certificate Store
        print("\n5️⃣ TEST CERTIFICATE STORE")
        
        cert_store = CertificateStore("./certificates/test_store")
        
        # Aggiungi certificati allo store
        for name, cert in certificates_loaded:
            alias = cert_store.add_certificate(cert, name.lower().replace(" ", "_"))
        
        # Lista certificati nello store
        store_certs = cert_store.list_certificates()
        print(f"   📚 Store contiene {len(store_certs)} certificati:")
        
        for cert_summary in store_certs:
            print(f"      - {cert_summary['alias']}: {cert_summary['common_name']} ({cert_summary['validity_status']})")
        
        # 6. Test salvataggio/caricamento
        print("\n6️⃣ TEST SALVATAGGIO E RICARICAMENTO")
        
        if certificates_loaded:
            test_cert = certificates_loaded[0][1]
            test_path = "./certificates/test_reload.pem"
            
            # Salva
            success = cert_manager.save_certificate_to_file(test_cert, test_path)
            
            if success:
                # Ricarica
                reloaded_cert = cert_manager.load_certificate_from_file(test_path)
                
                # Confronta
                original_info = cert_manager.parse_certificate(test_cert)
                reloaded_info = cert_manager.parse_certificate(reloaded_cert)
                
                if original_info.thumbprint_sha256 == reloaded_info.thumbprint_sha256:
                    print(f"   ✅ Certificato salvato e ricaricato correttamente")
                else:
                    print(f"   ❌ Errore: certificato modificato durante salvataggio/caricamento")
                
                # Cleanup
                Path(test_path).unlink(missing_ok=True)
        
        print("\n" + "✅" * 30)
        print("DEMO CERTIFICATE MANAGER COMPLETATA!")
        print("✅" * 30)
        
        return cert_manager, cert_store
        
    except Exception as e:
        print(f"\n❌ Errore durante demo: {e}")
        import traceback
        traceback.print_exc()
        return None, None


# =============================================================================
# 5. MAIN - PUNTO DI INGRESSO
# =============================================================================

if __name__ == "__main__":
    print("📋" * 40)
    print("CERTIFICATE MANAGER")
    print("Gestione e Validazione Certificati X.509")
    print("📋" * 40)
    
    # Esegui demo
    manager, store = demo_certificate_manager()
    
    if manager:
        print("\n🎉 Certificate Manager pronto!")
        print("\nFunzionalità disponibili:")
        print("✅ Caricamento certificati (PEM/DER)")
        print("✅ Parsing e analisi dettagliata")
        print("✅ Validazione catena certificati")
        print("✅ Controllo scadenze")
        print("✅ Estrazione chiavi pubbliche")
        print("✅ Certificate Store per collezioni")
        print("✅ Verifica firme")
    else:
        print("\n❌ Errore inizializzazione Certificate Manager")