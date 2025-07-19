"""Gestione e validazione di certificati X.509."""

import os
import datetime
import ipaddress
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from crypto.foundations import CryptoUtils


@dataclass
class CertificateInfo:
    """Informazioni estratte da un certificato X.509."""
    subject: str
    issuer: str
    serial_number: str
    not_valid_before: datetime.datetime
    not_valid_after: datetime.datetime
    thumbprint_sha256: str
    key_usage: List[str]
    extended_key_usage: List[str]
    subject_alt_names: List[str]
    is_ca: bool
    key_size: int
    signature_algorithm: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario per serializzazione."""
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
    """Rappresenta una catena di certificati."""
    end_entity: x509.Certificate
    intermediates: List[x509.Certificate]
    root_ca: x509.Certificate
    
    def get_full_chain(self) -> List[x509.Certificate]:
        """Ottiene la catena completa ordinata."""
        return [self.end_entity] + self.intermediates + [self.root_ca]
    
    def to_pem_bundle(self) -> str:
        """Converte la catena in bundle PEM."""
        pem_parts = []
        for cert in self.get_full_chain():
            pem_parts.append(cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'))
        return '\n'.join(pem_parts)


class CertificateManager:
    """Gestisce parsing, validazione e operazioni sui certificati X.509."""
    
    def __init__(self):
        """Inizializza il Certificate Manager."""
        self.backend = default_backend()
        self.crypto_utils = CryptoUtils()
        self.certificate_cache: Dict[str, x509.Certificate] = {}
        self.chain_cache: Dict[str, CertificateChain] = {}
    
    def load_certificate_from_file(self, file_path: str) -> x509.Certificate:
        """
        Carica un certificato da file PEM o DER.
        
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
            return self.certificate_cache[cache_key]
        
        try:
            cert_data = file_path.read_bytes()
            
            # Prova prima PEM, poi DER
            try:
                certificate = x509.load_pem_x509_certificate(cert_data, self.backend)
            except ValueError:
                certificate = x509.load_der_x509_certificate(cert_data, self.backend)
            
            # Salva in cache
            self.certificate_cache[cache_key] = certificate
            return certificate
            
        except Exception as e:
            raise RuntimeError(f"Errore caricamento certificato {file_path}: {e}")
    
    def load_certificate_from_bytes(self, cert_data: bytes, encoding: str = "PEM") -> x509.Certificate:
        """
        Carica un certificato da dati binari.
        
        Args:
            cert_data: Dati del certificato
            encoding: Encoding ("PEM" o "DER")
            
        Returns:
            Certificato X.509
        """
        try:
            if encoding.upper() == "PEM":
                return x509.load_pem_x509_certificate(cert_data, self.backend)
            elif encoding.upper() == "DER":
                return x509.load_der_x509_certificate(cert_data, self.backend)
            else:
                raise ValueError("Encoding deve essere 'PEM' o 'DER'")
        except Exception as e:
            raise RuntimeError(f"Errore caricamento certificato da bytes: {e}")
    
    def parse_certificate(self, certificate: x509.Certificate) -> CertificateInfo:
        """
        Estrae informazioni dettagliate da un certificato.
        
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
            
            # Estrae key usage
            key_usage_list = self._extract_key_usage(certificate)
            ext_key_usage_list = self._extract_extended_key_usage(certificate)
            san_list = self._extract_subject_alt_names(certificate)
            
            # Basic Constraints (CA)
            is_ca = self._is_ca_certificate(certificate)
            
            # Informazioni chiave
            public_key = certificate.public_key()
            key_size = public_key.key_size if isinstance(public_key, rsa.RSAPublicKey) else 0
            signature_algorithm = certificate.signature_algorithm_oid._name
            
            return CertificateInfo(
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
            
        except Exception as e:
            raise RuntimeError(f"Errore parsing certificato: {e}")
    
    def _extract_key_usage(self, certificate: x509.Certificate) -> List[str]:
        """Estrae le informazioni di Key Usage."""
        try:
            key_usage_ext = certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.KEY_USAGE
            ).value
            
            usage_list = []
            usage_attrs = [
                ('digital_signature', key_usage_ext.digital_signature),
                ('content_commitment', key_usage_ext.content_commitment),
                ('key_encipherment', key_usage_ext.key_encipherment),
                ('data_encipherment', key_usage_ext.data_encipherment),
                ('key_agreement', key_usage_ext.key_agreement),
                ('key_cert_sign', key_usage_ext.key_cert_sign),
                ('crl_sign', key_usage_ext.crl_sign)
            ]
            
            for name, is_present in usage_attrs:
                if is_present:
                    usage_list.append(name)
                    
            return usage_list or ["not_specified"]
            
        except x509.ExtensionNotFound:
            return ["not_specified"]
    
    def _extract_extended_key_usage(self, certificate: x509.Certificate) -> List[str]:
        """Estrae le informazioni di Extended Key Usage."""
        try:
            ext_key_usage_ext = certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
            ).value
            
            eku_map = {
                ExtendedKeyUsageOID.CODE_SIGNING: "code_signing",
                ExtendedKeyUsageOID.EMAIL_PROTECTION: "email_protection",
                ExtendedKeyUsageOID.SERVER_AUTH: "server_auth",
                ExtendedKeyUsageOID.CLIENT_AUTH: "client_auth"
            }
            
            return [eku_map.get(eku, str(eku)) for eku in ext_key_usage_ext]
            
        except x509.ExtensionNotFound:
            return []
    
    def _extract_subject_alt_names(self, certificate: x509.Certificate) -> List[str]:
        """Estrae i Subject Alternative Names."""
        try:
            san_ext = certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
            
            san_list = []
            for san in san_ext:
                if isinstance(san, x509.DNSName):
                    san_list.append(f"DNS:{san.value}")
                elif isinstance(san, x509.RFC822Name):
                    san_list.append(f"EMAIL:{san.value}")
                elif isinstance(san, x509.UniformResourceIdentifier):
                    san_list.append(f"URI:{san.value}")
                else:
                    san_list.append(f"OTHER:{str(san)}")
                    
            return san_list
            
        except x509.ExtensionNotFound:
            return []
    
    def _is_ca_certificate(self, certificate: x509.Certificate) -> bool:
        """Verifica se il certificato è una CA."""
        try:
            basic_constraints = certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            ).value
            return basic_constraints.ca
        except x509.ExtensionNotFound:
            return False
    
    def validate_certificate_chain(self, certificates: List[x509.Certificate], 
                                 trusted_ca_cert: x509.Certificate) -> Dict[str, Any]:
        """
        Valida una catena di certificati.
        
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
            
            # Prepara catena per verifica
            chain_to_verify = self._prepare_chain_for_verification(certificates, trusted_ca_cert)
            
            # Verifica ogni link nella catena
            self._verify_chain_links(chain_to_verify, result)
            
            # Verifica validità temporale
            self._verify_temporal_validity(chain_to_verify, result)
            
            # Verifica Basic Constraints per CA intermedie
            self._verify_ca_constraints(chain_to_verify, result)
            
            result['valid'] = len(result['errors']) == 0
            return result
            
        except Exception as e:
            result['errors'].append(f"Errore durante validazione: {e}")
            return result
    
    def _prepare_chain_for_verification(self, certificates: List[x509.Certificate],
                                      trusted_ca_cert: x509.Certificate) -> List[x509.Certificate]:
        """Prepara la catena per la verifica."""
        root_cert = certificates[-1] if len(certificates) > 1 else trusted_ca_cert
        
        if root_cert.subject != trusted_ca_cert.subject:
            return certificates + [trusted_ca_cert]
        return certificates
    
    def _verify_chain_links(self, chain: List[x509.Certificate], result: Dict) -> None:
        """Verifica i collegamenti nella catena."""
        for i in range(len(chain) - 1):
            current_cert = chain[i]
            issuer_cert = chain[i + 1]
            
            # Verifica issuer/subject
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
            except InvalidSignature:
                result['errors'].append(f"Firma non valida al livello {i}")
            except Exception as e:
                result['errors'].append(f"Errore verifica firma livello {i}: {e}")
    
    def _verify_temporal_validity(self, chain: List[x509.Certificate], result: Dict) -> None:
        """Verifica la validità temporale dei certificati."""
        now = datetime.datetime.utcnow()
        for i, cert in enumerate(chain):
            if now < cert.not_valid_before:
                result['errors'].append(f"Certificato {i} non ancora valido")
            elif now > cert.not_valid_after:
                result['errors'].append(f"Certificato {i} scaduto")
    
    def _verify_ca_constraints(self, chain: List[x509.Certificate], result: Dict) -> None:
        """Verifica i Basic Constraints per le CA intermedie."""
        for i in range(1, len(chain)):  # Salta end-entity
            cert = chain[i]
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                ).value
                
                if not basic_constraints.ca:
                    result['errors'].append(f"Certificato {i} non è marcato come CA")
                    
            except x509.ExtensionNotFound:
                result['warnings'].append(f"Certificato {i} manca Basic Constraints")
    
    def build_certificate_chain(self, end_entity_cert: x509.Certificate,
                               intermediate_certs: List[x509.Certificate],
                               root_ca_cert: x509.Certificate) -> CertificateChain:
        """
        Costruisce una catena di certificati ordinata.
        
        Args:
            end_entity_cert: Certificato end-entity
            intermediate_certs: Lista certificati intermedi
            root_ca_cert: Certificato root CA
            
        Returns:
            Catena di certificati ordinata
        """
        try:
            ordered_intermediates = self._order_intermediate_certificates(
                end_entity_cert, intermediate_certs, root_ca_cert
            )
            
            return CertificateChain(
                end_entity=end_entity_cert,
                intermediates=ordered_intermediates,
                root_ca=root_ca_cert
            )
        except Exception as e:
            raise RuntimeError(f"Errore costruzione catena: {e}")
    
    def _order_intermediate_certificates(self, end_entity: x509.Certificate,
                                       intermediates: List[x509.Certificate],
                                       root_ca: x509.Certificate) -> List[x509.Certificate]:
        """Ordina i certificati intermedi per costruire la catena corretta."""
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
                break
        
        return ordered
    
    def extract_public_key(self, certificate: x509.Certificate) -> rsa.RSAPublicKey:
        """
        Estrae la chiave pubblica da un certificato.
        
        Args:
            certificate: Certificato X.509
            
        Returns:
            Chiave pubblica RSA
        """
        try:
            public_key = certificate.public_key()
            
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise TypeError("Il certificato non contiene una chiave RSA")
            
            return public_key
        except Exception as e:
            raise RuntimeError(f"Errore estrazione chiave pubblica: {e}")
    
    def verify_certificate_signature(self, certificate: x509.Certificate,
                                   issuer_public_key: rsa.RSAPublicKey) -> bool:
        """
        Verifica la firma di un certificato.
        
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
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def check_certificate_expiry(self, certificate: x509.Certificate,
                               warning_days: int = 30) -> Dict[str, Any]:
        """
        Controlla la scadenza di un certificato.
        
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
            
            return result
        except Exception as e:
            result['status'] = f'error: {e}'
            return result
    
    def save_certificate_to_file(self, certificate: x509.Certificate, 
                                file_path: str, encoding: str = "PEM") -> bool:
        """
        Salva un certificato su file.
        
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
            
            file_path.write_bytes(cert_bytes)
            return True
        except Exception:
            return False
    
    def get_certificate_summary(self, certificate: x509.Certificate) -> Dict[str, Any]:
        """
        Ottiene un riassunto del certificato.
        
        Args:
            certificate: Certificato X.509
            
        Returns:
            Riassunto del certificato
        """
        try:
            cert_info = self.parse_certificate(certificate)
            expiry_info = self.check_certificate_expiry(certificate)
            
            return {
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
        except Exception as e:
            return {'error': f'Errore creazione riassunto: {e}'}
    
    def _get_common_name(self, certificate: x509.Certificate) -> str:
        """Estrae il Common Name dal certificato."""
        try:
            for attribute in certificate.subject:
                if attribute.oid == NameOID.COMMON_NAME:
                    return attribute.value
            return "N/A"
        except:
            return "N/A"
    
    def _get_organization(self, certificate: x509.Certificate) -> str:
        """Estrae l'Organization dal certificato."""
        try:
            for attribute in certificate.subject:
                if attribute.oid == NameOID.ORGANIZATION_NAME:
                    return attribute.value
            return "N/A"
        except:
            return "N/A"
    
    def _get_country(self, certificate: x509.Certificate) -> str:
        """Estrae il Country dal certificato."""
        try:
            for attribute in certificate.subject:
                if attribute.oid == NameOID.COUNTRY_NAME:
                    return attribute.value
            return "N/A"
        except:
            return "N/A"

    def generate_self_signed_cert(self, common_name: str, **kwargs) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Genera un certificato self-signed."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=kwargs.get('key_size', 2048),
            backend=default_backend()
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, kwargs.get('country', "IT")),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, kwargs.get('state', "Campania")),
            x509.NameAttribute(NameOID.LOCALITY_NAME, kwargs.get('locality', "Salerno")),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, kwargs.get('organization', "Academic Credentials")),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        builder = (x509.CertificateBuilder()
                  .subject_name(subject)
                  .issuer_name(issuer)
                  .public_key(private_key.public_key())
                  .serial_number(x509.random_serial_number())
                  .not_valid_before(datetime.datetime.utcnow())
                  .not_valid_after(datetime.datetime.utcnow() + 
                                 datetime.timedelta(days=kwargs.get('valid_days', 365)))
                  .add_extension(x509.BasicConstraints(ca=kwargs.get('ca', False), path_length=None), 
                               critical=True))
        
        # Aggiungi SANs se presenti
        if 'sans' in kwargs:
            san_names = []
            for san in kwargs['sans']:
                if san['type'] == 'DNS':
                    san_names.append(x509.DNSName(san['value']))
                elif san['type'] == 'IP':
                    san_names.append(x509.IPAddress(ipaddress.ip_address(san['value'])))
            
            if san_names:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(san_names),
                    critical=False
                )
        
        certificate = builder.sign(private_key, hashes.SHA256(), default_backend())
        return certificate, private_key


class CertificateStore:
    """Store per gestire collezioni di certificati."""
    
    def __init__(self, store_directory: str = "./certificates/store"):
        """
        Inizializza il certificate store.
        
        Args:
            store_directory: Directory per archiviare i certificati
        """
        self.store_dir = Path(store_directory)
        self.store_dir.mkdir(parents=True, exist_ok=True)
        
        self.certificates: Dict[str, x509.Certificate] = {}
        self.certificate_info: Dict[str, CertificateInfo] = {}
        self.cert_manager = CertificateManager()
    
    def add_certificate(self, certificate: x509.Certificate, alias: str = None) -> str:
        """
        Aggiunge un certificato allo store.
        
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
            
            return alias
        except Exception as e:
            raise RuntimeError(f"Errore aggiunta certificato: {e}")
    
    def get_certificate(self, alias: str) -> Optional[x509.Certificate]:
        """Ottiene un certificato per alias."""
        return self.certificates.get(alias)
    
    def list_certificates(self) -> List[Dict[str, Any]]:
        """Lista tutti i certificati nello store."""
        result = []
        
        for alias, cert in self.certificates.items():
            summary = self.cert_manager.get_certificate_summary(cert)
            summary['alias'] = alias
            result.append(summary)
        
        return result
    
    def remove_certificate(self, alias: str) -> bool:
        """Rimuove un certificato dallo store."""
        try:
            if alias in self.certificates:
                del self.certificates[alias]
                del self.certificate_info[alias]
                
                cert_file = self.store_dir / f"{alias}.pem"
                if cert_file.exists():
                    cert_file.unlink()
                
                return True
            return False
        except Exception:
            return False
    
    def load_certificates_from_directory(self, directory: str) -> int:
        """
        Carica tutti i certificati da una directory.
        
        Args:
            directory: Directory contenente certificati PEM
            
        Returns:
            Numero di certificati caricati
        """
        directory = Path(directory)
        loaded_count = 0
        
        if not directory.exists():
            return 0
        
        for cert_file in directory.glob("*.pem"):
            try:
                certificate = self.cert_manager.load_certificate_from_file(str(cert_file))
                alias = cert_file.stem
                self.add_certificate(certificate, alias)
                loaded_count += 1
            except Exception:
                continue
        
        return loaded_count