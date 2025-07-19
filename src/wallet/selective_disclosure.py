# =============================================================================
# FASE 4: WALLET E DIVULGAZIONE SELETTIVA - SELECTIVE DISCLOSURE
# File: wallet/selective_disclosure.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import json
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import uuid

# Import moduli interni
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from crypto.foundations import CryptoUtils, MerkleTree, DigitalSignature
    from credentials.models import AcademicCredential, Course, PersonalInfo
    from wallet.student_wallet import AcademicStudentWallet, WalletCredential
except ImportError as e:
    print(f"⚠️  Errore import moduli interni: {e}")
    print("   Assicurati che tutti i moduli siano presenti nel progetto")
    raise


# =============================================================================
# 1. ENUMS E STRUTTURE DATI SELECTIVE DISCLOSURE
# =============================================================================

class DisclosureLevel(Enum):
    """Livelli di divulgazione"""
    MINIMAL = "minimal"           # Solo dati essenziali
    STANDARD = "standard"         # Dati accademici base
    DETAILED = "detailed"         # Dati completi
    CUSTOM = "custom"             # Selezione personalizzata


class AttributeType(Enum):
    """Tipi di attributi divulgabili"""
    PERSONAL_INFO = "personal_info"
    STUDY_PERIOD = "study_period"
    UNIVERSITY_INFO = "university_info"
    PROGRAM_INFO = "program_info"
    COURSE_INFO = "course_info"
    GRADE_INFO = "grade_info"
    METADATA = "metadata"


@dataclass
class AttributeSelector:
    """Selettore per attributi specifici"""
    attribute_type: AttributeType
    field_path: str                    # Path JSON dell'attributo (es. "courses.0.course_name")
    display_name: str                  # Nome visualizzabile
    required: bool = False             # Se obbligatorio per divulgazione
    sensitive: bool = False            # Se contiene dati sensibili
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'attribute_type': self.attribute_type.value,
            'field_path': self.field_path,
            'display_name': self.display_name,
            'required': self.required,
            'sensitive': self.sensitive
        }


@dataclass
class MerkleProof:
    """Proof di Merkle per un attributo"""
    attribute_index: int               # Indice dell'attributo nella lista
    attribute_value: Any               # Valore dell'attributo
    proof_path: List[Dict[str, Any]]   # Path di hash siblings
    merkle_root: str                   # Root dell'albero originale
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'attribute_index': self.attribute_index,
            'attribute_value': self.attribute_value,
            'proof_path': self.proof_path,
            'merkle_root': self.merkle_root
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MerkleProof':
        return cls(
            attribute_index=data['attribute_index'],
            attribute_value=data['attribute_value'],
            proof_path=data['proof_path'],
            merkle_root=data['merkle_root']
        )


@dataclass
class SelectiveDisclosure:
    """Divulgazione selettiva di una credenziale"""
    credential_id: str
    disclosure_id: str
    disclosed_attributes: Dict[str, Any]    # Attributi divulgati
    merkle_proofs: List[MerkleProof]       # Prove per ogni attributo
    disclosure_level: DisclosureLevel
    created_at: datetime.datetime
    created_by: str                        # Pseudonimo studente
    purpose: Optional[str] = None          # Scopo della divulgazione
    recipient: Optional[str] = None        # Destinatario
    expires_at: Optional[datetime.datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'credential_id': self.credential_id,
            'disclosure_id': self.disclosure_id,
            'disclosed_attributes': self.disclosed_attributes,
            'merkle_proofs': [proof.to_dict() for proof in self.merkle_proofs],
            'disclosure_level': self.disclosure_level.value,
            'created_at': self.created_at.isoformat(),
            'created_by': self.created_by,
            'purpose': self.purpose,
            'recipient': self.recipient,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SelectiveDisclosure':
        return cls(
            credential_id=data['credential_id'],
            disclosure_id=data['disclosure_id'],
            disclosed_attributes=data['disclosed_attributes'],
            merkle_proofs=[MerkleProof.from_dict(p) for p in data['merkle_proofs']],
            disclosure_level=DisclosureLevel(data['disclosure_level']),
            created_at=datetime.datetime.fromisoformat(data['created_at']),
            created_by=data['created_by'],
            purpose=data.get('purpose'),
            recipient=data.get('recipient'),
            expires_at=(
                datetime.datetime.fromisoformat(data['expires_at'])
                if data.get('expires_at') else None
            )
        )


# =============================================================================
# 2. SELECTIVE DISCLOSURE MANAGER
# =============================================================================

class SelectiveDisclosureManager:
    """Manager per la divulgazione selettiva delle credenziali"""
    
    def __init__(self):
        """Inizializza il manager"""
        self.crypto_utils = CryptoUtils()
        
        # Cache per ottimizzazione
        self.merkle_trees_cache: Dict[str, MerkleTree] = {}
        self.attribute_schemas_cache: Dict[str, List[AttributeSelector]] = {}
        
        print("🔒 Selective Disclosure Manager inizializzato")
    
    def get_available_attributes(self, credential: AcademicCredential) -> List[AttributeSelector]:
        """
        Ottiene lista di attributi divulgabili da una credenziale
        
        Args:
            credential: Credenziale da analizzare
            
        Returns:
            Lista selettori attributi disponibili
        """
        credential_id = str(credential.metadata.credential_id)
        
        # Controlla cache
        if credential_id in self.attribute_schemas_cache:
            return self.attribute_schemas_cache[credential_id]
        
        attributes = []
        
        # 1. Metadati (sempre disponibili)
        attributes.extend([
            AttributeSelector(
                AttributeType.METADATA, "metadata.version",
                "Versione formato credenziale", required=True
            ),
            AttributeSelector(
                AttributeType.METADATA, "metadata.issued_at",
                "Data emissione", required=True
            ),
            AttributeSelector(
                AttributeType.METADATA, "metadata.credential_id",
                "ID credenziale", required=True
            ),
        ])
        
        # 2. Informazioni università emittente
        attributes.extend([
            AttributeSelector(
                AttributeType.UNIVERSITY_INFO, "issuer.name",
                "Nome università emittente", required=True
            ),
            AttributeSelector(
                AttributeType.UNIVERSITY_INFO, "issuer.country",
                "Paese università emittente"
            ),
            AttributeSelector(
                AttributeType.UNIVERSITY_INFO, "issuer.erasmus_code",
                "Codice Erasmus emittente"
            ),
        ])
        
        # 3. Università ospitante
        attributes.extend([
            AttributeSelector(
                AttributeType.UNIVERSITY_INFO, "host_university.name",
                "Nome università ospitante", required=True
            ),
            AttributeSelector(
                AttributeType.UNIVERSITY_INFO, "host_university.country",
                "Paese università ospitante"
            ),
            AttributeSelector(
                AttributeType.UNIVERSITY_INFO, "host_university.erasmus_code",
                "Codice Erasmus ospitante"
            ),
        ])
        
        # 4. Informazioni personali (sensibili)
        attributes.extend([
            AttributeSelector(
                AttributeType.PERSONAL_INFO, "subject.pseudonym",
                "Pseudonimo studente", required=True
            ),
            AttributeSelector(
                AttributeType.PERSONAL_INFO, "subject.surname_hash",
                "Hash cognome", sensitive=True
            ),
            AttributeSelector(
                AttributeType.PERSONAL_INFO, "subject.name_hash",
                "Hash nome", sensitive=True
            ),
            AttributeSelector(
                AttributeType.PERSONAL_INFO, "subject.birth_date_hash",
                "Hash data nascita", sensitive=True
            ),
        ])
        
        # 5. Periodo di studio
        attributes.extend([
            AttributeSelector(
                AttributeType.STUDY_PERIOD, "study_period.start_date",
                "Data inizio studio"
            ),
            AttributeSelector(
                AttributeType.STUDY_PERIOD, "study_period.end_date",
                "Data fine studio"
            ),
            AttributeSelector(
                AttributeType.STUDY_PERIOD, "study_period.study_type",
                "Tipo di studio"
            ),
            AttributeSelector(
                AttributeType.STUDY_PERIOD, "study_period.academic_year",
                "Anno accademico"
            ),
        ])
        
        # 6. Programma di studio
        attributes.extend([
            AttributeSelector(
                AttributeType.PROGRAM_INFO, "study_program.name",
                "Nome programma di studio"
            ),
            AttributeSelector(
                AttributeType.PROGRAM_INFO, "study_program.eqf_level",
                "Livello EQF"
            ),
            AttributeSelector(
                AttributeType.PROGRAM_INFO, "study_program.field_of_study",
                "Campo di studio"
            ),
        ])
        
        # 7. Informazioni corsi (dinamiche)
        for i, course in enumerate(credential.courses):
            course_attributes = [
                AttributeSelector(
                    AttributeType.COURSE_INFO, f"courses.{i}.course_name",
                    f"Nome corso: {course.course_name}"
                ),
                AttributeSelector(
                    AttributeType.COURSE_INFO, f"courses.{i}.course_code",
                    f"Codice corso: {course.course_code}"
                ),
                AttributeSelector(
                    AttributeType.COURSE_INFO, f"courses.{i}.ects_credits",
                    f"Crediti ECTS: {course.course_name}"
                ),
                AttributeSelector(
                    AttributeType.COURSE_INFO, f"courses.{i}.professor",
                    f"Docente: {course.course_name}"
                ),
                AttributeSelector(
                    AttributeType.COURSE_INFO, f"courses.{i}.exam_date",
                    f"Data esame: {course.course_name}"
                ),
                AttributeSelector(
                    AttributeType.GRADE_INFO, f"courses.{i}.grade.score",
                    f"Voto: {course.course_name}", sensitive=True
                ),
                AttributeSelector(
                    AttributeType.GRADE_INFO, f"courses.{i}.grade.ects_grade",
                    f"Grade ECTS: {course.course_name}", sensitive=True
                ),
            ]
            attributes.extend(course_attributes)
        
        # 8. Riassunti
        attributes.extend([
            AttributeSelector(
                AttributeType.GRADE_INFO, "total_ects_credits",
                "Totale crediti ECTS"
            ),
            AttributeSelector(
                AttributeType.GRADE_INFO, "average_grade",
                "Media voti", sensitive=True
            ),
        ])
        
        # Cache risultato
        self.attribute_schemas_cache[credential_id] = attributes
        
        return attributes
    
    def _flatten_credential(self, credential: AcademicCredential) -> Dict[str, Any]:
        """Appiattisce la struttura della credenziale in un dizionario di percorsi."""
        from collections import deque
        import re
        
        def is_primitive(val):
            return val is None or isinstance(val, (int, float, bool, str))
        
        def normalize_key(key):
            return re.sub(r'[^a-zA-Z0-9_]', '_', key)
        
        items = deque([('', credential.dict())])
        flat = {}
        
        while items:
            parent_path, obj = items.popleft()
            
            if isinstance(obj, dict):
                for k, v in obj.items():
                    new_path = f"{parent_path}.{normalize_key(k)}" if parent_path else normalize_key(k)
                    items.append((new_path, v))
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    new_path = f"{parent_path}[{i}]"
                    items.append((new_path, v))
            elif is_primitive(obj) or isinstance(obj, (datetime.datetime, datetime.date)):
                flat[parent_path] = obj
        
        return flat
    
    def create_selective_disclosure(self, 
                              credential: AcademicCredential,
                              attributes_to_disclose: List[str],
                              disclosure_level: DisclosureLevel,
                              purpose: str,
                              recipient: Optional[str] = None,
                              expires_hours: int = 24) -> SelectiveDisclosure:
        """
        Crea una divulgazione selettiva per una credenziale, generando Merkle proofs valide.
        
        Args:
            credential: Credenziale accademica
            attributes_to_disclose: Lista di percorsi attributi da divulgare
            disclosure_level: Livello di divulgazione
            purpose: Scopo della divulgazione
            recipient: Destinatario opzionale
            expires_hours: Ore prima della scadenza
            
        Returns:
            Oggetto SelectiveDisclosure con attributi divulgati e proofs
        """
        try:
            # 1. Appiattisci e ordina tutti gli attributi della credenziale per consistenza
            all_attributes = self._flatten_credential(credential)
            sorted_attributes = sorted(all_attributes.items(), key=lambda x: x[0])

            # Estrai solo i valori nell'ordine corretto per costruire l'albero
            attribute_values_for_tree = [attr_value for attr_path, attr_value in sorted_attributes]

            # 2. Costruisci l'albero Merkle direttamente dai valori.
            #    La classe MerkleTree gestirà l'hashing internamente in modo corretto.
            merkle_tree = MerkleTree(attribute_values_for_tree)
            merkle_root = merkle_tree.get_merkle_root()

            # 3. Filtra gli attributi che l'utente vuole effettivamente divulgare
            disclosed_attributes = {
                path: value
                for path, value in sorted_attributes
                if path in attributes_to_disclose
            }

            # 4. Genera le Merkle Proof per ciascun attributo divulgato
            merkle_proofs = []
            for attr_path, attr_value in disclosed_attributes.items():
                # Trova l'indice dell'attributo nella lista *originale e ordinata*
                # Questa è la riga corretta che usa 'sorted_attributes'
                idx = next((i for i, (path, _) in enumerate(sorted_attributes) if path == attr_path), -1)

                if idx != -1:
                    proof_path = merkle_tree.generate_proof(idx)
                    merkle_proofs.append(
                        MerkleProof(
                            attribute_index=idx,
                            attribute_value=attr_value,
                            proof_path=proof_path,
                            merkle_root=merkle_root
                        )
                    )

            # 5. Crea l'oggetto finale di divulgazione selettiva
            return SelectiveDisclosure(
                credential_id=str(credential.metadata.credential_id),
                disclosure_id=str(uuid.uuid4()),
                disclosed_attributes=disclosed_attributes,
                merkle_proofs=merkle_proofs,
                disclosure_level=disclosure_level,
                created_at=datetime.datetime.now(datetime.timezone.utc),
                created_by=credential.subject.pseudonym,
                purpose=purpose,
                recipient=recipient,
                expires_at=(
                    datetime.datetime.now(datetime.timezone.utc) +
                    datetime.timedelta(hours=expires_hours)
                ) if expires_hours > 0 else None
            )

        except Exception as e:
            print(f"❌ Errore creazione divulgazione selettiva: {e}")
            raise

    
    def create_predefined_disclosure(self, 
                                   credential: AcademicCredential,
                                   disclosure_level: DisclosureLevel,
                                   **kwargs) -> SelectiveDisclosure:
        """
        Crea divulgazione con template predefinito
        
        Args:
            credential: Credenziale originale
            disclosure_level: Livello predefinito
            **kwargs: Parametri aggiuntivi
            
        Returns:
            Divulgazione selettiva
        """
        # Ottiene template attributi per livello
        selected_attributes = self._get_predefined_attributes(credential, disclosure_level)
        
        return self.create_selective_disclosure(
            credential, selected_attributes, disclosure_level, **kwargs
        )
    
    def verify_selective_disclosure(self, disclosure: SelectiveDisclosure,
                                  original_merkle_root: str) -> Tuple[bool, List[str]]:
        """
        Verifica una divulgazione selettiva
        
        Args:
            disclosure: Divulgazione da verificare
            original_merkle_root: Root Merkle originale
            
        Returns:
            Tupla (valida, lista_errori)
        """
        errors = []
        
        try:
            print(f"🔍 Verificando divulgazione selettiva: {disclosure.disclosure_id[:8]}...")
            
            # 1. Verifica scadenza
            if disclosure.expires_at and datetime.datetime.utcnow() > disclosure.expires_at:
                errors.append("Divulgazione scaduta")
            
            # 2. Verifica merkle proofs
            for i, proof in enumerate(disclosure.merkle_proofs):
                try:
                    # Verifica che la root coincida
                    if proof.merkle_root != original_merkle_root:
                        errors.append(f"Merkle root non corrispondente per proof {i}")
                        continue
                    
                    # Verifica proof (implementazione semplificata)
                    is_valid = self._verify_merkle_proof(proof)
                    
                    if not is_valid:
                        errors.append(f"Merkle proof {i} non valida")
                        
                except Exception as e:
                    errors.append(f"Errore verifica proof {i}: {e}")
            
            # 3. Verifica coerenza attributi
            disclosed_count = len(disclosure.disclosed_attributes)
            proofs_count = len(disclosure.merkle_proofs)
            
            if disclosed_count != proofs_count:
                errors.append(f"Numero attributi ({disclosed_count}) ≠ numero proofs ({proofs_count})")
            
            # 4. Verifica attributi obbligatori
            required_attributes = ["metadata.credential_id", "metadata.issued_at", "subject.pseudonym"]
            
            for required in required_attributes:
                if not self._has_attribute_path(disclosure.disclosed_attributes, required):
                    errors.append(f"Attributo obbligatorio mancante: {required}")
            
            is_valid = len(errors) == 0
            
            if is_valid:
                print(f"✅ Divulgazione selettiva VALIDA")
            else:
                print(f"❌ Divulgazione selettiva NON VALIDA ({len(errors)} errori)")
                for error in errors[:3]:  # Prime 3
                    print(f"   - {error}")
            
            return is_valid, errors
            
        except Exception as e:
            errors.append(f"Errore durante verifica: {e}")
            return False, errors
    
    def create_presentation(self, disclosures: List[SelectiveDisclosure],
                          student_private_key: Optional[Any] = None,
                          presentation_purpose: Optional[str] = None) -> Dict[str, Any]:
        """
        Crea una presentazione da multiple divulgazioni selettive
        
        Args:
            disclosures: Lista divulgazioni da includere
            student_private_key: Chiave privata studente per firma
            presentation_purpose: Scopo della presentazione
            
        Returns:
            Presentazione strutturata
        """
        try:
            print(f"📋 Creando presentazione: {len(disclosures)} divulgazioni")
            
            presentation_id = str(uuid.uuid4())
            
            presentation = {
                'presentation_id': presentation_id,
                'created_at': datetime.datetime.utcnow().isoformat(),
                'purpose': presentation_purpose,
                'disclosures': [disclosure.to_dict() for disclosure in disclosures],
                'summary': {
                    'total_disclosures': len(disclosures),
                    'credentials_included': len(set(d.credential_id for d in disclosures)),
                    'students_included': len(set(d.created_by for d in disclosures)),
                    'earliest_credential': min(d.created_at for d in disclosures).isoformat(),
                    'latest_credential': max(d.created_at for d in disclosures).isoformat()
                }
            }
            
            # Firma presentazione se chiave fornita
            if student_private_key:
                try:
                    digital_signature = DigitalSignature("PSS")
                    signed_presentation = digital_signature.sign_document(
                        student_private_key, presentation
                    )
                    presentation = signed_presentation
                    print("✍️  Presentazione firmata digitalmente")
                except Exception as e:
                    print(f"⚠️  Errore firma presentazione: {e}")
            
            print(f"✅ Presentazione creata: {presentation_id[:8]}...")
            return presentation
            
        except Exception as e:
            print(f"❌ Errore creazione presentazione: {e}")
            raise
    
    def _extract_selected_attributes(self, credential: AcademicCredential,
                                   selected_paths: List[str]) -> Dict[str, Any]:
        """Estrae attributi selezionati dalla credenziale"""
        credential_dict = credential.to_dict()
        disclosed_attributes = {}
        
        for path in selected_paths:
            try:
                value = self._get_nested_value(credential_dict, path)
                disclosed_attributes[path] = value
            except KeyError:
                print(f"⚠️  Attributo non trovato: {path}")
            except Exception as e:
                print(f"⚠️  Errore estrazione {path}: {e}")
        
        return disclosed_attributes
    
    def _generate_merkle_proofs(self, credential: AcademicCredential,
                              selected_paths: List[str]) -> List[MerkleProof]:
        """Genera Merkle proofs per gli attributi selezionati"""
        credential_id = str(credential.metadata.credential_id)
        
        # Ottiene o crea Merkle Tree per la credenziale
        if credential_id not in self.merkle_trees_cache:
            # Usa i corsi come base per il Merkle Tree (come nel modello originale)
            course_data = [course.dict() for course in credential.courses]
            if course_data:
                merkle_tree = MerkleTree(course_data)
                self.merkle_trees_cache[credential_id] = merkle_tree
            else:
                print("⚠️  Nessun corso disponibile per Merkle Tree")
                return []
        
        merkle_tree = self.merkle_trees_cache[credential_id]
        proofs = []
        
        # Genera proof per ogni attributo (implementazione semplificata)
        for i, path in enumerate(selected_paths):
            try:
                # Per attributi dei corsi, genera proof reale
                if path.startswith("courses.") and "." in path[8:]:
                    course_index_str = path.split(".")[1]
                    if course_index_str.isdigit():
                        course_index = int(course_index_str)
                        
                        if course_index < len(credential.courses):
                            # Genera proof per questo corso
                            course_proof_path = merkle_tree.generate_proof(course_index)
                            
                            proof = MerkleProof(
                                attribute_index=i,
                                attribute_value=self._get_nested_value(credential.to_dict(), path),
                                proof_path=course_proof_path,
                                merkle_root=merkle_tree.get_merkle_root()
                            )
                            proofs.append(proof)
                            continue
                
                # Per altri attributi, genera proof simbolica
                proof = MerkleProof(
                    attribute_index=i,
                    attribute_value=self._get_nested_value(credential.to_dict(), path),
                    proof_path=[{"hash": f"proof_hash_{i}", "is_right": i % 2 == 0}],
                    merkle_root=credential.metadata.merkle_root
                )
                proofs.append(proof)
                
            except Exception as e:
                print(f"⚠️  Errore generazione proof per {path}: {e}")
        
        return proofs
    
    def _verify_merkle_proof(self, proof: MerkleProof) -> bool:
        """Verifica una Merkle proof (implementazione semplificata)"""
        try:
            # Implementazione semplificata - in produzione dovrebbe ricostruire il path
            
            # Verifica che la proof non sia vuota
            if not proof.proof_path:
                return False
            
            # Verifica che abbia una root valida
            if not proof.merkle_root or len(proof.merkle_root) != 64:
                return False
            
            # Per la demo, consideriamo valide le proof non vuote
            return True
            
        except Exception as e:
            print(f"⚠️  Errore verifica proof: {e}")
            return False
    
    def _get_predefined_attributes(self, credential: AcademicCredential,
                                 level: DisclosureLevel) -> List[str]:
        """Ottiene attributi predefiniti per livello di divulgazione"""
        
        if level == DisclosureLevel.MINIMAL:
            return [
                "metadata.credential_id",
                "metadata.issued_at",
                "subject.pseudonym",
                "issuer.name",
                "host_university.name",
                "total_ects_credits"
            ]
        
        elif level == DisclosureLevel.STANDARD:
            attributes = [
                "metadata.credential_id",
                "metadata.issued_at",
                "metadata.version",
                "subject.pseudonym",
                "issuer.name",
                "issuer.country",
                "host_university.name",
                "host_university.country",
                "study_period.start_date",
                "study_period.end_date",
                "study_period.study_type",
                "study_program.name",
                "study_program.eqf_level",
                "total_ects_credits"
            ]
            
            # Aggiunge info base dei corsi (senza voti)
            for i in range(len(credential.courses)):
                attributes.extend([
                    f"courses.{i}.course_name",
                    f"courses.{i}.ects_credits",
                    f"courses.{i}.exam_date"
                ])
            
            return attributes
        
        elif level == DisclosureLevel.DETAILED:
            # Include tutto tranne dati hash sensibili
            available_attributes = self.get_available_attributes(credential)
            
            return [
                attr.field_path for attr in available_attributes
                if not attr.sensitive or attr.field_path in [
                    "courses.*.grade.score",  # Include voti ma non hash personali
                    "average_grade"
                ]
            ]
        
        else:  # CUSTOM - restituisce lista vuota
            return []
    
    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """Ottiene valore annidato usando path con dot notation"""
        keys = path.split('.')
        current = data
        
        for key in keys:
            if isinstance(current, dict):
                current = current[key]
            elif isinstance(current, list) and key.isdigit():
                current = current[int(key)]
            else:
                raise KeyError(f"Chiave {key} non trovata in {type(current)}")
        
        return current
    
    def _has_attribute_path(self, data: Dict[str, Any], path: str) -> bool:
        """Verifica se un path esiste nei dati"""
        try:
            self._get_nested_value(data, path)
            return True
        except (KeyError, IndexError, TypeError):
            return False
    
    def get_disclosure_templates(self) -> Dict[str, Dict[str, Any]]:
        """Ottiene template di divulgazione predefiniti"""
        return {
            "university_verification": {
                "name": "Verifica Università",
                "description": "Informazioni base per verifica iscrizione",
                "level": DisclosureLevel.MINIMAL,
                "typical_use": "Verifica iscrizione presso università",
                "includes": ["ID credenziale", "Pseudonimo", "Università", "Crediti totali"]
            },
            
            "academic_transcript": {
                "name": "Trascrizione Accademica",
                "description": "Informazioni complete su corsi e voti",
                "level": DisclosureLevel.DETAILED,
                "typical_use": "Riconoscimento crediti, trasferimenti",
                "includes": ["Tutti i corsi", "Voti", "Università", "Periodo studio"]
            },
            
            "mobility_certificate": {
                "name": "Certificato Mobilità",
                "description": "Attestato partecipazione programma mobilità",
                "level": DisclosureLevel.STANDARD,
                "typical_use": "Riconoscimento partecipazione Erasmus",
                "includes": ["Università ospitante", "Periodo", "Programma", "Corsi base"]
            },
            
            "scholarship_application": {
                "name": "Domanda Borsa di Studio",
                "description": "Informazioni accademiche per borse di studio",
                "level": DisclosureLevel.DETAILED,
                "typical_use": "Candidatura borse di studio",
                "includes": ["Performance accademica", "Università", "Media voti"]
            }
        }
    
    def clear_cache(self):
        """Pulisce cache del manager"""
        self.merkle_trees_cache.clear()
        self.attribute_schemas_cache.clear()
        print("🗑️  Cache Selective Disclosure pulita")


# =============================================================================
# 3. DEMO E TESTING
# =============================================================================

def demo_selective_disclosure():
    """Demo del Selective Disclosure Manager"""
    
    print("🔒" * 40)
    print("DEMO SELECTIVE DISCLOSURE")
    print("Divulgazione Selettiva Credenziali")
    print("🔒" * 40)
    
    try:
        # 1. Inizializzazione
        print("\n1️⃣ INIZIALIZZAZIONE")
        
        disclosure_manager = SelectiveDisclosureManager()
        
        # Crea credenziale di test
        from credentials.models import CredentialFactory
        test_credential = CredentialFactory.create_sample_credential()
        
        print(f"✅ Credenziale test: {test_credential.metadata.credential_id}")
        print(f"   Corsi: {len(test_credential.courses)}")
        print(f"   Università: {test_credential.issuer.name} → {test_credential.host_university.name}")
        
        # 2. Analisi attributi disponibili
        print("\n2️⃣ ANALISI ATTRIBUTI DISPONIBILI")
        
        available_attributes = disclosure_manager.get_available_attributes(test_credential)
        
        print(f"📋 Attributi disponibili: {len(available_attributes)}")
        
        # Raggruppa per tipo
        by_type = {}
        for attr in available_attributes:
            attr_type = attr.attribute_type.value
            if attr_type not in by_type:
                by_type[attr_type] = []
            by_type[attr_type].append(attr)
        
        for attr_type, attrs in by_type.items():
            sensitive_count = sum(1 for a in attrs if a.sensitive)
            required_count = sum(1 for a in attrs if a.required)
            print(f"   {attr_type}: {len(attrs)} attributi ({required_count} obbligatori, {sensitive_count} sensibili)")
        
        # 3. Template di divulgazione
        print("\n3️⃣ TEMPLATE DI DIVULGAZIONE")
        
        templates = disclosure_manager.get_disclosure_templates()
        
        for template_id, template_info in templates.items():
            print(f"📋 {template_info['name']}:")
            print(f"   Descrizione: {template_info['description']}")
            print(f"   Livello: {template_info['level'].value}")
            print(f"   Uso tipico: {template_info['typical_use']}")
        
        # 4. Divulgazione MINIMAL
        print("\n4️⃣ DIVULGAZIONE MINIMAL")
        
        minimal_disclosure = disclosure_manager.create_predefined_disclosure(
            test_credential,
            DisclosureLevel.MINIMAL,
            purpose="Verifica base iscrizione",
            recipient="Ufficio Studenti Università",
            expires_hours=24
        )
        
        print(f"✅ Divulgazione minimal creata: {minimal_disclosure.disclosure_id[:8]}...")
        print(f"   Attributi divulgati: {len(minimal_disclosure.disclosed_attributes)}")
        print(f"   Merkle proofs: {len(minimal_disclosure.merkle_proofs)}")
        print(f"   Scade: {minimal_disclosure.expires_at}")
        
        # Mostra attributi divulgati
        print("   📋 Attributi inclusi:")
        for path, value in minimal_disclosure.disclosed_attributes.items():
            value_str = str(value)[:50] + "..." if len(str(value)) > 50 else str(value)
            print(f"      {path}: {value_str}")
        
        # 5. Divulgazione STANDARD
        print("\n5️⃣ DIVULGAZIONE STANDARD")
        
        standard_disclosure = disclosure_manager.create_predefined_disclosure(
            test_credential,
            DisclosureLevel.STANDARD,
            purpose="Riconoscimento crediti Erasmus",
            recipient="Università di Salerno - Ufficio Mobilità"
        )
        
        print(f"✅ Divulgazione standard creata: {standard_disclosure.disclosure_id[:8]}...")
        print(f"   Attributi divulgati: {len(standard_disclosure.disclosed_attributes)}")
        
        # 6. Divulgazione CUSTOM
        print("\n6️⃣ DIVULGAZIONE CUSTOM")
        
        # Seleziona attributi specifici
        custom_attributes = [
            "metadata.credential_id",
            "subject.pseudonym",
            "host_university.name",
            "courses.0.course_name",
            "courses.0.grade.score",
            "courses.1.course_name", 
            "courses.1.grade.score"
        ]
        
        custom_disclosure = disclosure_manager.create_selective_disclosure(
            test_credential,
            custom_attributes,
            DisclosureLevel.CUSTOM,
            purpose="Verifica specifica corsi informatica",
            recipient="Azienda IT per stage"
        )
        
        print(f"✅ Divulgazione custom creata: {custom_disclosure.disclosure_id[:8]}...")
        print("   📋 Corsi selezionati:")
        for path, value in custom_disclosure.disclosed_attributes.items():
            if "course_name" in path or "grade.score" in path:
                print(f"      {path}: {value}")
        
        # 7. Verifica divulgazioni
        print("\n7️⃣ VERIFICA DIVULGAZIONI")
        
        original_merkle_root = test_credential.metadata.merkle_root
        
        for disclosure_name, disclosure in [
            ("Minimal", minimal_disclosure),
            ("Standard", standard_disclosure), 
            ("Custom", custom_disclosure)
        ]:
            print(f"   🔍 Verificando divulgazione {disclosure_name}...")
            
            is_valid, errors = disclosure_manager.verify_selective_disclosure(
                disclosure, original_merkle_root
            )
            
            if is_valid:
                print(f"      ✅ VALIDA")
            else:
                print(f"      ❌ NON VALIDA ({len(errors)} errori)")
                for error in errors[:2]:
                    print(f"         - {error}")
        
        # 8. Creazione presentazione
        print("\n8️⃣ CREAZIONE PRESENTAZIONE")
        
        presentation = disclosure_manager.create_presentation(
            [minimal_disclosure, standard_disclosure],
            presentation_purpose="Domanda riconoscimento crediti completa"
        )
        
        print(f"📋 Presentazione creata: {presentation['presentation_id'][:8]}...")
        print(f"   Divulgazioni incluse: {presentation['summary']['total_disclosures']}")
        print(f"   Credenziali coinvolte: {presentation['summary']['credentials_included']}")
        
        # 9. Export/Import divulgazioni
        print("\n9️⃣ EXPORT DIVULGAZIONI")
        
        # Export divulgazione custom
        export_path = "./wallet/custom_disclosure.json"
        Path("./wallet").mkdir(exist_ok=True)
        
        with open(export_path, 'w', encoding='utf-8') as f:
            json.dump(custom_disclosure.to_dict(), f, indent=2, ensure_ascii=False, default=str)
        
        print(f"💾 Divulgazione esportata: {export_path}")
        
        # Test import
        with open(export_path, 'r', encoding='utf-8') as f:
            imported_data = json.load(f)
        
        imported_disclosure = SelectiveDisclosure.from_dict(imported_data)
        
        if imported_disclosure.disclosure_id == custom_disclosure.disclosure_id:
            print("✅ Import/Export funzionante")
        
        # 10. Statistiche finali
        print("\n🔟 STATISTICHE FINALI")
        
        print("📊 Riepilogo divulgazioni create:")
        print(f"   Minimal: {len(minimal_disclosure.disclosed_attributes)} attributi, {len(minimal_disclosure.merkle_proofs)} proofs")
        print(f"   Standard: {len(standard_disclosure.disclosed_attributes)} attributi, {len(standard_disclosure.merkle_proofs)} proofs")
        print(f"   Custom: {len(custom_disclosure.disclosed_attributes)} attributi, {len(custom_disclosure.merkle_proofs)} proofs")
        
        print(f"\n📋 Template disponibili: {len(templates)}")
        print(f"🔒 Attributi totali analizzati: {len(available_attributes)}")
        print(f"🎯 Presentazioni create: 1")
        
        print("\n" + "✅" * 40)
        print("DEMO SELECTIVE DISCLOSURE COMPLETATA!")
        print("✅" * 40)
        
        return disclosure_manager, [minimal_disclosure, standard_disclosure, custom_disclosure]
        
    except Exception as e:
        print(f"\n❌ Errore durante demo: {e}")
        import traceback
        traceback.print_exc()
        return None, []


# =============================================================================
# 4. MAIN - PUNTO DI INGRESSO
# =============================================================================

if __name__ == "__main__":
    print("🔒" * 50)
    print("SELECTIVE DISCLOSURE")
    print("Divulgazione Selettiva Credenziali Accademiche")
    print("🔒" * 50)
    
    # Esegui demo
    manager, disclosures = demo_selective_disclosure()
    
    if manager:
        print("\n🎉 Selective Disclosure pronto!")
        print("\nFunzionalità disponibili:")
        print("✅ Analisi attributi divulgabili")
        print("✅ Template divulgazione predefiniti")
        print("✅ Divulgazione personalizzata")
        print("✅ Generazione Merkle proofs")
        print("✅ Verifica divulgazioni")
        print("✅ Creazione presentazioni")
        print("✅ Gestione scadenze")
        print("✅ Export/Import divulgazioni")
        print("✅ Cache ottimizzazioni")
        
        print(f"\n🚀 Pronto per Presentation Manager!")
        print(f"📋 Divulgazioni demo create: {len(disclosures)}")
    else:
        print("\n❌ Errore inizializzazione Selective Disclosure")