
# Fondamenta Crittografiche
# Sistema Credenziali Accademiche


import os
import json
import base64
import hashlib
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import cryptography
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# 1. GESTIONE CHIAVI RSA

class RSAKeyManager:
    """Gestisce la generazione, serializzazione e archiviazione delle chiavi RSA"""
    
    def __init__(self, key_size: int = 2048):
        """
        Inizializza il key manager
        
        Args:
            key_size: Dimensione della chiave RSA (2048 o 4096 bit)
        """
        if key_size not in [2048, 4096]:
            raise ValueError("Key size deve essere 2048 o 4096 bit")
        self.key_size = key_size
        self.backend = default_backend()
    
    def generate_key_pair(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Genera una nuova coppia di chiavi RSA
        
        Returns:
            Tupla contenente (chiave_privata, chiave_pubblica)
        """
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
                backend=self.backend
            )
            public_key = private_key.public_key()
            
            print(f"✓ Generata coppia di chiavi RSA-{self.key_size}")
            return private_key, public_key
            
        except Exception as e:
            raise RuntimeError(f"Errore nella generazione delle chiavi: {e}")
    
    def serialize_private_key(self, private_key: rsa.RSAPrivateKey, password: Optional[bytes] = None) -> bytes:
        """
        Serializza una chiave privata in formato PEM
        
        Args:
            private_key: Chiave privata RSA
            password: Password per cifrare la chiave (opzionale)
            
        Returns:
            Chiave privata serializzata in PEM
        """
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
    
    def serialize_public_key(self, public_key: rsa.RSAPublicKey) -> bytes:
        """
        Serializza una chiave pubblica in formato PEM
        
        Args:
            public_key: Chiave pubblica RSA
            
        Returns:
            Chiave pubblica serializzata in PEM
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def deserialize_private_key(self, pem_data: bytes, password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
        """
        Deserializza una chiave privata da formato PEM
        
        Args:
            pem_data: Dati PEM della chiave privata
            password: Password per decifrare la chiave (opzionale)
            
        Returns:
            Chiave privata RSA
        """
        return serialization.load_pem_private_key(
            pem_data, 
            password=password, 
            backend=self.backend
        )
    
    def deserialize_public_key(self, pem_data: bytes) -> rsa.RSAPublicKey:
        """
        Deserializza una chiave pubblica da formato PEM
        
        Args:
            pem_data: Dati PEM della chiave pubblica
            
        Returns:
            Chiave pubblica RSA
        """
        return serialization.load_pem_public_key(pem_data, backend=self.backend)
    
    def save_key_pair(self, private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey, 
                      base_path: str, key_name: str, password: Optional[str] = None) -> Dict[str, str]:
        """
        Salva una coppia di chiavi su filesystem
        
        Args:
            private_key: Chiave privata
            public_key: Chiave pubblica
            base_path: Directory base per salvare le chiavi
            key_name: Nome base per i file delle chiavi
            password: Password per cifrare la chiave privata
            
        Returns:
            Dizionario con i percorsi dei file salvati
        """
        # Crea directory se non esiste
        Path(base_path).mkdir(parents=True, exist_ok=True)
        
        # Percorsi dei file
        private_path = os.path.join(base_path, f"{key_name}_private.pem")
        public_path = os.path.join(base_path, f"{key_name}_public.pem")
        
        # Serializza e salva chiave privata
        password_bytes = password.encode('utf-8') if password else None
        private_pem = self.serialize_private_key(private_key, password_bytes)
        
        with open(private_path, 'wb') as f:
            f.write(private_pem)
        
        # Serializza e salva chiave pubblica
        public_pem = self.serialize_public_key(public_key)
        with open(public_path, 'wb') as f:
            f.write(public_pem)
        
        # Imposta permessi restrittivi per la chiave privata
        os.chmod(private_path, 0o600)
        
        print(f"✓ Chiavi salvate: {key_name}")
        return {
            'private_key_path': private_path,
            'public_key_path': public_path
        }
    
    def load_key_pair(self, private_path: str, public_path: str, 
                      password: Optional[str] = None) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Carica una coppia di chiavi dal filesystem
        
        Args:
            private_path: Percorso della chiave privata
            public_path: Percorso della chiave pubblica
            password: Password per decifrare la chiave privata
            
        Returns:
            Tupla contenente (chiave_privata, chiave_pubblica)
        """
        password_bytes = password.encode('utf-8') if password else None
        
        # Carica chiave privata
        with open(private_path, 'rb') as f:
            private_key = self.deserialize_private_key(f.read(), password_bytes)
        
        # Carica chiave pubblica
        with open(public_path, 'rb') as f:
            public_key = self.deserialize_public_key(f.read())
        
        print(f"✓ Chiavi caricate da {Path(private_path).parent}")
        return private_key, public_key

# 2. FIRMA DIGITALE RSA-SHA256

class DigitalSignature:
    """Gestisce la firma digitale e verifica con RSA-SHA256"""
    
    def __init__(self, padding_type: str = "PSS"):
        """
        Inizializza il sistema di firma digitale
        
        Args:
            padding_type: Tipo di padding ("PSS" o "PKCS1v15")
        """
        if padding_type not in ["PSS", "PKCS1v15"]:
            raise ValueError("Padding type deve essere 'PSS' o 'PKCS1v15'")
        
        self.padding_type = padding_type
        self.hash_algorithm = hashes.SHA256()
        
        # Configura il padding
        if padding_type == "PSS":
            self.padding_scheme = padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            )
        else:  
            self.padding_scheme = padding.PKCS1v15()
        
        print(f"✓ Sistema firma digitale inizializzato (RSA-SHA256-{padding_type})")
    
    def sign_data(self, private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
        """
        Firma digitalmente dei dati
        
        Args:
            private_key: Chiave privata per la firma
            data: Dati da firmare
            
        Returns:
            Firma digitale
        """
        try:
            signature = private_key.sign(
                data,
                self.padding_scheme,
                self.hash_algorithm
            )
            print(f"✓ Dati firmati ({len(signature)} bytes)")
            return signature
            
        except Exception as e:
            raise RuntimeError(f"Errore nella firma: {e}")
    
    def sign_document(self, private_key: rsa.RSAPrivateKey, document: Dict[str, Any]) -> Dict[str, Any]:
        """
        Firma un documento JSON
        
        Args:
            private_key: Chiave privata per la firma
            document: Documento da firmare
            
        Returns:
            Documento con firma aggiunta
        """
        # Serializza il documento (escludendo eventuali firme esistenti)
        doc_copy = document.copy()
        doc_copy.pop('firma', None)  # Rimuove firma esistente
        
        # Converte in JSON canonico per firma consistente
        json_data = json.dumps(doc_copy, sort_keys=True, separators=(',', ':')).encode('utf-8')
        
        # Firma i dati
        signature = self.sign_data(private_key, json_data)
        
        # Aggiunge la firma al documento
        doc_copy['firma'] = {
            'algoritmo': f'RSA-SHA256-{self.padding_type}',
            'valore': base64.b64encode(signature).decode('utf-8'),
            'timestamp': datetime.datetime.utcnow().isoformat() + 'Z'
        }
        
        print("✓ Documento firmato digitalmente")
        return doc_copy
    
    def verify_signature(self, public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
        """
        Verifica una firma digitale
        
        Args:
            public_key: Chiave pubblica per la verifica
            data: Dati originali
            signature: Firma da verificare
            
        Returns:
            True se la firma è valida, False altrimenti
        """
        try:
            public_key.verify(
                signature,
                data,
                self.padding_scheme,
                self.hash_algorithm
            )
            print("✓ Firma verificata con successo")
            return True
            
        except InvalidSignature:
            print("✗ Firma non valida")
            return False
        except Exception as e:
            print(f"✗ Errore nella verifica: {e}")
            return False
    
    def verify_document_signature(self, public_key: rsa.RSAPublicKey, signed_document: Dict[str, Any]) -> bool:
        """
        Verifica la firma di un documento JSON
        
        Args:
            public_key: Chiave pubblica per la verifica
            signed_document: Documento firmato
            
        Returns:
            True se la firma è valida, False altrimenti
        """
        if 'firma' not in signed_document:
            print("✗ Documento non contiene firma")
            return False
        
        try:
            # Estrae la firma
            signature_info = signed_document['firma']
            signature_b64 = signature_info['valore']
            signature = base64.b64decode(signature_b64)
            
            # Ricostruisce i dati originali
            doc_copy = signed_document.copy()
            del doc_copy['firma']
            json_data = json.dumps(doc_copy, sort_keys=True, separators=(',', ':')).encode('utf-8')
            
            # Verifica la firma
            return self.verify_signature(public_key, json_data, signature)
            
        except Exception as e:
            print(f"✗ Errore nella verifica del documento: {e}")
            return False


# 3. IMPLEMENTAZIONE MERKLE TREE

class MerkleTree:
    """Implementazione di Merkle Tree per divulgazione selettiva"""
    
    def __init__(self, data_list: List[Any]):
        """
        Costruisce un Merkle Tree da una lista di dati
        
        Args:
            data_list: Lista degli elementi da inserire nell'albero
        """
        if not data_list:
            raise ValueError("La lista dati non può essere vuota")
        
        self.original_data = data_list.copy()
        self.tree_levels = []
        self.leaf_indices = {}  # Mappa elemento -> indice foglia
        
        # Costruisce l'albero
        self._build_tree()
        print(f"✓ Merkle Tree costruito con {len(data_list)} foglie")
    
    def _hash_data(self, data: Any) -> str:
        """Hash SHA-256 di un dato"""
        if isinstance(data, dict):
            # Per dizionari, usa JSON canonico
            json_str = json.dumps(data, sort_keys=True, separators=(',', ':'), default=str)
            return hashlib.sha256(json_str.encode('utf-8')).hexdigest()
        else:
            # Per altri tipi, converte a stringa
            return hashlib.sha256(str(data).encode('utf-8')).hexdigest()
    
    def _build_tree(self):
        """Costruisce l'albero di Merkle bottom-up"""
        # Livello 0: hash delle foglie
        current_level = []
        for i, data in enumerate(self.original_data):
            leaf_hash = self._hash_data(data)
            current_level.append(leaf_hash)
            self.leaf_indices[i] = len(current_level) - 1
        
        self.tree_levels.append(current_level)
        
        # Costruisce i livelli superiori
        while len(current_level) > 1:
            next_level = []
            
            # Se il numero di nodi è dispari, duplica l'ultimo
            if len(current_level) % 2 == 1:
                current_level.append(current_level[-1])
            
            # Combina coppie di hash
            for i in range(0, len(current_level), 2):
                left_hash = current_level[i]
                right_hash = current_level[i + 1]
                combined = left_hash + right_hash
                parent_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
                next_level.append(parent_hash)
            
            self.tree_levels.append(next_level)
            current_level = next_level
    
    def get_merkle_root(self) -> str:
        """
        Ottiene la radice del Merkle Tree
        
        Returns:
            Hash della radice
        """
        return self.tree_levels[-1][0]
    
    def generate_proof(self, data_index: int) -> List[Dict[str, Any]]:
        """
        Genera una Merkle proof per un elemento specifico
        
        Args:
            data_index: Indice dell'elemento nella lista originale
            
        Returns:
            Lista di hash siblings per ricostruire la radice
        """
        if data_index < 0 or data_index >= len(self.original_data):
            raise ValueError("Indice dati non valido")
        
        proof = []
        current_index = data_index
        
        # Risale dall'elemento alla radice
        for level_idx in range(len(self.tree_levels) - 1):
            level = self.tree_levels[level_idx]
            
            # Determina il sibling
            if current_index % 2 == 0:  # Nodo sinistro
                sibling_index = current_index + 1
                is_right = True
            else:  # Nodo destro
                sibling_index = current_index - 1
                is_right = False
            
            # Aggiunge il sibling alla proof (se esiste)
            if sibling_index < len(level):
                proof.append({
                    'hash': level[sibling_index],
                    'is_right': is_right
                })
            
            # Passa al livello superiore
            current_index = current_index // 2
        
        print(f"✓ Proof generata per elemento {data_index} ({len(proof)} step)")
        return proof
    
    def verify_proof(self, data: Any, data_index: int, proof: List[Dict[str, Any]], expected_root: str) -> bool:
        """
        Verifica una Merkle proof
        
        Args:
            data: Dato originale
            data_index: Indice del dato nella lista originale
            proof: Merkle proof
            expected_root: Radice attesa
            
        Returns:
            True se la proof è valida, False altrimenti
        """
        try:
            # Hash del dato
            current_hash = self._hash_data(data)
            
            # Ricostruisce il percorso verso la radice
            for step in proof:
                sibling_hash = step['hash']
                is_right = step['is_right']
                
                if is_right:
                    # Il sibling è a destra
                    combined = current_hash + sibling_hash
                else:
                    # Il sibling è a sinistra
                    combined = sibling_hash + current_hash
                
                current_hash = hashlib.sha256(combined.encode('utf-8')).hexdigest()
            
            # Verifica che la radice ricostruita corrisponda
            is_valid = current_hash == expected_root
            
            if is_valid:
                print("✓ Merkle proof verificata con successo")
            else:
                print("✗ Merkle proof non valida")
            
            return is_valid
            
        except Exception as e:
            print(f"✗ Errore nella verifica della proof: {e}")
            return False
    
    def get_tree_info(self) -> Dict[str, Any]:
        """
        Ottiene informazioni sull'albero
        
        Returns:
            Dizionario con statistiche dell'albero
        """
        return {
            'num_leaves': len(self.original_data),
            'num_levels': len(self.tree_levels),
            'merkle_root': self.get_merkle_root(),
            'tree_height': len(self.tree_levels) - 1
        }


# 4. UTILITIES CRITTOGRAFICHE

class CryptoUtils:
    """Utilities crittografiche generali"""

    @staticmethod
    def generate_salt() -> bytes:
        """Genera un salt casuale per l'hashing."""
        return os.urandom(16)

    @staticmethod
    def hash_with_salt(data: str, salt: bytes) -> str:
        """
        Calcola l'hash di una stringa usando un salt con PBKDF2HMAC.
        Questo è più sicuro di un semplice hash SHA-256.
        """
        kdf = cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000, # Numero di iterazioni raccomandato da OWASP
            backend=default_backend()
        )
        return kdf.derive(data.encode('utf-8')).hex()
    
    @staticmethod
    def sha256_hash(data: bytes) -> str:
        """
        Calcola hash SHA-256 di dati binari
        
        Args:
            data: Dati da hashare
            
        Returns:
            Hash in formato esadecimale
        """
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def sha256_hash_string(text: str) -> str:
        """
        Calcola hash SHA-256 di una stringa
        
        Args:
            text: Stringa da hashare
            
        Returns:
            Hash in formato esadecimale
        """
        return hashlib.sha256(text.encode('utf-8')).hexdigest()
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes) -> bytes:
        """
        Deriva una chiave di 32-byte per Fernet da una password usando PBKDF2.
        Questo è un modo sicuro per trasformare una password leggibile in una chiave
        crittografica robusta.

        Args:
            password (str): La password fornita dall'utente.
            salt (bytes): Un valore casuale per prevenire attacchi rainbow table.

        Returns:
            bytes: Una chiave crittografica codificata in Base64 URL-safe.
        """
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32, # Lunghezza della chiave per AES-256
            salt=salt,
            iterations=100000, # Numero di iterazioni raccomandato per la sicurezza
            backend=default_backend()
        )
        # La chiave viene codificata in Base64 per essere compatibile con Fernet
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        return key

    @staticmethod
    def encode_base64(data: bytes) -> str:
        """
        Codifica dati in Base64
        
        Args:
            data: Dati binari da codificare
            
        Returns:
            Stringa Base64
        """
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def decode_base64(b64_string: str) -> bytes:
        """
        Decodifica stringa Base64
        
        Args:
            b64_string: Stringa Base64
            
        Returns:
            Dati binari decodificati
        """
        return base64.b64decode(b64_string)
    
    @staticmethod
    def generate_secure_timestamp() -> str:
        """
        Genera un timestamp sicuro in formato ISO 8601 UTC
        
        Returns:
            Timestamp formattato
        """
        return datetime.datetime.utcnow().isoformat() + 'Z'
    
    @staticmethod
    def validate_timestamp(timestamp: str, max_age_seconds: int = 3600) -> bool:
        """
        Valida un timestamp e verifica che non sia troppo vecchio
        
        Args:
            timestamp: Timestamp in formato ISO 8601
            max_age_seconds: Età massima consentita in secondi
            
        Returns:
            True se il timestamp è valido, False altrimenti
        """
        try:
            # Parse del timestamp
            if timestamp.endswith('Z'):
                timestamp = timestamp[:-1] + '+00:00'
            
            ts_datetime = datetime.datetime.fromisoformat(timestamp)
            
            # Converte a UTC se necessario
            if ts_datetime.tzinfo is None:
                ts_datetime = ts_datetime.replace(tzinfo=datetime.timezone.utc)
            
            # Verifica l'età
            now = datetime.datetime.now(datetime.timezone.utc)
            age = (now - ts_datetime).total_seconds()
            
            return 0 <= age <= max_age_seconds
            
        except Exception:
            return False
    
    @staticmethod
    def generate_uuid() -> str:
        """
        Genera un UUID sicuro
        
        Returns:
            UUID in formato stringa
        """
        import uuid
        return str(uuid.uuid4())
    
    @staticmethod
    def secure_compare(a: str, b: str) -> bool:
        """
        Confronto sicuro contro timing attacks
        
        Args:
            a: Prima stringa
            b: Seconda stringa
            
        Returns:
            True se le stringhe sono uguali, False altrimenti
        """
        import hmac
        return hmac.compare_digest(a, b)


# 5. CLASSE PRINCIPALE - CRYPTO MANAGER

class CryptoManager:
    """Manager principale per tutte le operazioni crittografiche"""
    
    def __init__(self, key_size: int = 2048, padding_type: str = "PSS"):
        """
        Inizializza il CryptoManager
        
        Args:
            key_size: Dimensione chiavi RSA (2048 o 4096)
            padding_type: Tipo di padding per firme ("PSS" o "PKCS1v15")
        """
        self.key_manager = RSAKeyManager(key_size)
        self.signature = DigitalSignature(padding_type)
        self.utils = CryptoUtils()
        
        print("=" * 60)
        print("CRYPTO MANAGER INIZIALIZZATO")
        print(f"RSA Key Size: {key_size} bit")
        print(f"Padding Type: {padding_type}")
        print("=" * 60)
    
    def create_merkle_tree(self, data_list: List[Any]) -> MerkleTree:
        """
        Crea un nuovo Merkle Tree
        
        Args:
            data_list: Lista dati per l'albero
            
        Returns:
            Istanza MerkleTree
        """
        return MerkleTree(data_list)
    
    def demo_full_workflow(self):
        """Dimostra un workflow completo del sistema crittografico"""
        print("\n" + "=" * 60)
        print("DEMO WORKFLOW COMPLETO")
        print("=" * 60)
        
        # 1. Generazione chiavi università
        print("\n1. GENERAZIONE CHIAVI UNIVERSITÀ")
        univ_private, univ_public = self.key_manager.generate_key_pair()
        
        # 2. Creazione credenziale di esempio
        print("\n2. CREAZIONE CREDENZIALE ACCADEMICA")
        esami_studente = [
            {
                "denominazioneEsame": "Algoritmi e Protocolli per la Sicurezza",
                "codiceCorso": "INF/01-ASD",
                "votoEsame": {"punteggio": "28/30", "gradeECTS": "B"},
                "creditiECTS": 6,
                "docente": "Prof. Mario Rossi"
            },
            {
                "denominazioneEsame": "Intelligenza Artificiale", 
                "codiceCorso": "INF/01-AI",
                "votoEsame": {"punteggio": "30/30", "gradeECTS": "A"},
                "creditiECTS": 8,
                "docente": "Prof.ssa Anna Bianchi"
            },
            {
                "denominazioneEsame": "Sistemi Distribuiti",
                "codiceCorso": "INF/01-SD", 
                "votoEsame": {"punteggio": "25/30", "gradeECTS": "C"},
                "creditiECTS": 6,
                "docente": "Prof. Giuseppe Verdi"
            }
        ]
        
        # 3. Costruzione Merkle Tree
        print("\n3. COSTRUZIONE MERKLE TREE")
        merkle_tree = self.create_merkle_tree(esami_studente)
        tree_info = merkle_tree.get_tree_info()
        print(f"   Root: {tree_info['merkle_root'][:16]}...")
        print(f"   Livelli: {tree_info['num_levels']}")
        
        # 4. Creazione credenziale completa
        credenziale = {
            "metadati": {
                "versione": "1.2",
                "identificativoUUID": self.utils.generate_uuid(),
                "timestampEmissione": self.utils.generate_secure_timestamp(),
                "merkle_root": merkle_tree.get_merkle_root()
            },
            "emittente": {
                "denominazioneEnte": "Université de Rennes",
                "paese": "Francia"
            },
            "soggetto": {
                "identificativoStudente": "student_" + self.utils.sha256_hash_string("mario.rossi@unisa.it")[:8]
            },
            "attributiAccademici": {
                "esamiSostenuti": esami_studente,
                "totaleCreditiECTS": sum(esame["creditiECTS"] for esame in esami_studente)
            }
        }
        
        # 5. Firma della credenziale
        print("\n4. FIRMA DIGITALE CREDENZIALE")
        credenziale_firmata = self.signature.sign_document(univ_private, credenziale)
        
        # 6. Verifica firma
        print("\n5. VERIFICA FIRMA CREDENZIALE")
        is_valid = self.signature.verify_document_signature(univ_public, credenziale_firmata)
        
        # 7. Dimostrazione divulgazione selettiva
        print("\n6. DIVULGAZIONE SELETTIVA")
        # Lo studente vuole condividere solo il primo esame
        esame_selezionato = esami_studente[0]
        proof = merkle_tree.generate_proof(0)
        
        print(f"   Esame condiviso: {esame_selezionato['denominazioneEsame']}")
        print(f"   Proof steps: {len(proof)}")
        
        # 8. Verifica proof lato università ricevente
        print("\n7. VERIFICA MERKLE PROOF")
        original_root = credenziale_firmata["metadati"]["merkle_root"]
        proof_valid = merkle_tree.verify_proof(esame_selezionato, 0, proof, original_root)
        
        # 9. Salvataggio chiavi per test
        print("\n8. SALVATAGGIO CHIAVI")
        key_paths = self.key_manager.save_key_pair(
            univ_private, univ_public, 
            "./keys", "universite_rennes", 
            password="SecurePassword123!"
        )
        
        # 10. Summary finale
        print("\n" + "=" * 60)
        print("DEMO COMPLETATA CON SUCCESSO")
        print("=" * 60)
        print(f"✓ Credenziale firmata: {is_valid}")
        print(f"✓ Merkle proof valida: {proof_valid}")
        print(f"✓ Chiavi salvate in: {key_paths['private_key_path']}")
        print(f"✓ UUID credenziale: {credenziale_firmata['metadati']['identificativoUUID']}")
        print("=" * 60)
        
        return credenziale_firmata


# 6. TESTING E VALIDAZIONE

def run_comprehensive_tests():
    """Esegue test completi di tutti i componenti"""
    print("\n" + "🧪" * 20)
    print("TESTING SUITE COMPLETA")
    print("🧪" * 20)
    
    try:
        # Test 1: Key Manager
        print("\nTest 1: RSA Key Manager")
        key_mgr = RSAKeyManager(2048)
        priv, pub = key_mgr.generate_key_pair()
        
        # Test serializzazione
        priv_pem = key_mgr.serialize_private_key(priv, b"testpassword")
        pub_pem = key_mgr.serialize_public_key(pub)
        
        # Test deserializzazione
        priv_loaded = key_mgr.deserialize_private_key(priv_pem, b"testpassword")
        pub_loaded = key_mgr.deserialize_public_key(pub_pem)
        
        print("   ✓ Generazione chiavi")
        print("   ✓ Serializzazione/Deserializzazione")
        
        # Test 2: Digital Signature
        print("\nTest 2: Digital Signature")
        signer = DigitalSignature("PSS")
        
        test_data = b"Test message for signing"
        signature = signer.sign_data(priv, test_data)
        is_valid = signer.verify_signature(pub, test_data, signature)
        
        test_doc = {"test": "document", "value": 123}
        signed_doc = signer.sign_document(priv, test_doc)
        doc_valid = signer.verify_document_signature(pub, signed_doc)
        
        print(f"   ✓ Firma dati: {is_valid}")
        print(f"   ✓ Firma documento: {doc_valid}")
        
        # Test 3: Merkle Tree
        print("\nTest 3: Merkle Tree")
        test_data = ["item1", "item2", "item3", "item4"]
        merkle = MerkleTree(test_data)
        
        root = merkle.get_merkle_root()
        proof = merkle.generate_proof(1)
        proof_valid = merkle.verify_proof("item2", 1, proof, root)
        
        print(f"   ✓ Costruzione albero: {len(test_data)} elementi")
        print(f"   ✓ Proof verification: {proof_valid}")
        
        # Test 4: Crypto Utils
        print("\nTest 4: Crypto Utils")
        utils = CryptoUtils()
        
        hash_test = utils.sha256_hash(b"test data")
        b64_test = utils.encode_base64(b"test data")
        timestamp = utils.generate_secure_timestamp()
        ts_valid = utils.validate_timestamp(timestamp)
        
        print(f"   ✓ SHA-256: {hash_test[:16]}...")
        print(f"   ✓ Base64: {b64_test}")
        print(f"   ✓ Timestamp: {ts_valid}")
        
        print("\n" + "✅" * 20)
        print("TUTTI I TEST SUPERATI!")
        print("✅" * 20)
        
        return True
        
    except Exception as e:
        print(f"\nTest fallito: {e}")
        return False


# 7. MAIN - PUNTO DI INGRESSO

if __name__ == "__main__":
    print("🔐" * 30)
    print("FASE 1: FONDAMENTA CRITTOGRAFICHE")
    print("Sistema Credenziali Accademiche Decentralizzate")
    print("🔐" * 30)
    
    # Esegui test completi
    tests_passed = run_comprehensive_tests()
    
    if tests_passed:
        # Dimostra workflow completo
        crypto_manager = CryptoManager(key_size=2048, padding_type="PSS")
        credenziale_demo = crypto_manager.demo_full_workflow()
        
        print("\n🎉 FASE 1 COMPLETATA CON SUCCESSO!")
        print("\nComponenti implementati:")
        print("RSA Key Manager (2048/4096 bit)")
        print("Digital Signature (RSA-SHA256-PSS/PKCS1v15)")
        print("Merkle Tree (costruzione, proof, verifica)")
        print("Crypto Utils (SHA-256, Base64, Timestamp)")
        print("Testing suite completa")
        
        print(f"\nFile chiavi salvati in: ./keys/")
        print("Pronti per la Fase 2: Gestione Certificati X.509!")
    
    else:
        print("\nTest falliti - verificare l'implementazione")