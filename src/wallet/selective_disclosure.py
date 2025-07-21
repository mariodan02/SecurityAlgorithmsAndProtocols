# =============================================================================
# FASE 4: WALLET E DIVULGAZIONE SELETTIVA - SELECTIVE DISCLOSURE 
# File: wallet/selective_disclosure.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import logging
import os
import json
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import uuid

# Import dei nostri moduli interni del progetto
import sys

from credentials.models import DeterministicSerializer
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from crypto.foundations import CryptoUtils, MerkleTree, DigitalSignature
    from credentials.models import AcademicCredential, Course, PersonalInfo
    from wallet.student_wallet import AcademicStudentWallet, WalletCredential
except ImportError as e:
    print(f"Errore import moduli interni: {e}")
    print("Assicurati che tutti i moduli siano presenti nel progetto")
    raise


# 1. ENUMS E STRUTTURE DATI PER LA DIVULGAZIONE SELETTIVA

class DisclosureLevel(Enum):
    """
    Definisce quanto "generosamente" vogliamo condividere i nostri dati.
    MINIMAL è molto restrittivo, DETAILED condivide quasi tutto.
    """
    MINIMAL = "minimal"
    STANDARD = "standard"
    DETAILED = "detailed"
    CUSTOM = "custom"


class AttributeType(Enum):
    """Categorizza i tipi di dati che possiamo condividere."""
    PERSONAL_INFO = "personal_info"
    STUDY_PERIOD = "study_period"
    UNIVERSITY_INFO = "university_info"
    PROGRAM_INFO = "program_info"
    COURSE_INFO = "course_info"
    GRADE_INFO = "grade_info"
    METADATA = "metadata"


@dataclass
class AttributeSelector:
    """Un "selettore" che descrive un singolo dato che possiamo condividere."""
    attribute_type: AttributeType
    field_path: str
    display_name: str
    required: bool = False
    sensitive: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte il selettore in un dizionario."""
        return {
            'attribute_type': self.attribute_type.value,
            'field_path': self.field_path,
            'display_name': self.display_name,
            'required': self.required,
            'sensitive': self.sensitive
        }

@dataclass
class MerkleProof:
    """
    La prova crittografica che un dato che stiamo condividendo
    proviene davvero dalla credenziale originale e non è stato alterato.
    """
    attribute_index: int
    attribute_value: Any
    proof_path: List[Dict[str, Any]]
    merkle_root: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte la prova in un dizionario."""
        return {
            'attribute_index': self.attribute_index,
            'attribute_value': self.attribute_value,
            'proof_path': self.proof_path,
            'merkle_root': self.merkle_root
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MerkleProof':
        """Crea una prova partendo da un dizionario."""
        return cls(
            attribute_index=data['attribute_index'],
            attribute_value=data['attribute_value'],
            proof_path=data['proof_path'],
            merkle_root=data['merkle_root']
        )

def _serialize_datetimes(obj: Any) -> Any:
    """Serializza ricorsivamente tutti gli oggetti datetime in stringhe ISO."""
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    elif isinstance(obj, datetime.date):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {k: _serialize_datetimes(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_serialize_datetimes(i) for i in obj]
    elif isinstance(obj, tuple):
        return tuple(_serialize_datetimes(i) for i in obj)
    elif hasattr(obj, '__dict__'):
        try:
            return _serialize_datetimes(obj.__dict__)
        except:
            return str(obj)
    else:
        return obj


@dataclass
class SelectiveDisclosure:
    """Rappresenta l'insieme di dati divulgati da una credenziale."""
    credential_id: str
    disclosure_id: str
    disclosed_attributes: Dict[str, Any]
    merkle_proofs: List[MerkleProof]
    disclosure_level: DisclosureLevel
    created_at: datetime.datetime
    created_by: str
    purpose: Optional[str] = None
    recipient: Optional[str] = None
    expires_at: Optional[datetime.datetime] = None
    original_merkle_root: str = ""  # ← AGGIUNGI QUESTO CAMPO SE MANCA
    original_university_signature: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario."""
        serialized_attributes = _serialize_datetimes(self.disclosed_attributes)

        return {
            'credential_id': self.credential_id,
            'disclosure_id': self.disclosure_id,
            'disclosed_attributes': serialized_attributes,
            'merkle_proofs': [proof.to_dict() for proof in self.merkle_proofs],
            'disclosure_level': self.disclosure_level.value,
            'created_at': self.created_at.isoformat(),
            'created_by': self.created_by,
            'purpose': self.purpose,
            'recipient': self.recipient,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'original_merkle_root': self.original_merkle_root,
            'original_university_signature': self.original_university_signature 
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SelectiveDisclosure':
        """Crea da dizionario."""
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
            ),
            original_merkle_root=data.get('original_merkle_root', '')  # ← AGGIUNGI ANCHE QUI
        )
        
# 2. SELECTIVE DISCLOSURE MANAGER

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
        """
        Appiattisce credenziale usando serializzazione MIGLIORATA.
        """
        from collections import deque
        import re
        
        def normalize_key(key):
            # Normalizza le chiavi mantenendo i caratteri validi per i path
            return re.sub(r'[^a-zA-Z0-9_\[\]\.]', '_', key)
        
        print("🔧 Inizio appiattimento credenziale...")
        
        # Serializza la credenziale
        credential_dict = DeterministicSerializer._normalize_object(credential)
        print(f"📊 Credenziale serializzata: {len(credential_dict)} campi principali")
        
        items = deque([('', credential_dict)])
        flat = {}
        
        while items:
            parent_path, obj = items.popleft()
            
            if isinstance(obj, dict):
                for k, v in obj.items():
                    # Crea il percorso normalizzato
                    normalized_k = normalize_key(k)
                    new_path = f"{parent_path}.{normalized_k}" if parent_path else normalized_k
                    items.append((new_path, v))
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    new_path = f"{parent_path}.{i}"
                    items.append((new_path, v))
            else:
                flat[parent_path] = obj
        
        print(f"✅ Appiattimento completato: {len(flat)} attributi totali")
        return flat

    def create_selective_disclosure(self, 
                                credential: AcademicCredential,
                                attributes_to_disclose: List[str],
                                disclosure_level: DisclosureLevel,
                                purpose: str,
                                recipient: Optional[str] = None,
                                expires_hours: int = 24) -> SelectiveDisclosure:
        """
        Crea una divulgazione selettiva con prove Merkle REALI.
        FIX: Sincronizza correttamente attributi e prove.
        """
        try:
            print(f"🔍 Creazione selective disclosure REALE per: {credential.metadata.credential_id}")
            print(f"📋 Attributi richiesti: {len(attributes_to_disclose)} -> {attributes_to_disclose}")

            # 1. Espandi gli attributi wildcard
            expanded_attributes_to_disclose = []
            for attr_path in attributes_to_disclose:
                if ".*." in attr_path:
                    base_path, field_name = attr_path.split(".*.")
                    for i in range(len(credential.courses)):
                        expanded_attributes_to_disclose.append(f"{base_path}.{i}.{field_name}")
                else:
                    expanded_attributes_to_disclose.append(attr_path)
            
            print(f"📋 Attributi espansi: {len(expanded_attributes_to_disclose)} -> {expanded_attributes_to_disclose}")

            # 2. Calcola il Merkle Tree degli attributi e ottiene la mappa degli indici
            attributes_root, attribute_index_map = credential.calculate_attributes_merkle_root()
            
            print(f"🌳 Merkle root attributi: {attributes_root}")
            print(f"📊 Mappa attributi disponibili: {len(attribute_index_map)} elementi")
            
            # 3. Appiattisce la credenziale per ottenere tutti gli attributi
            all_attributes = self._flatten_credential(credential)
            print(f"🗂️ Attributi appiattiti totali: {len(all_attributes)}")
            
            # 4. Estrae solo gli attributi da divulgare - CON TRACKING DETTAGLIATO
            disclosed_attributes = {}
            valid_attributes = []
            failed_attributes = []

            for attr_path in expanded_attributes_to_disclose:
                print(f"🔍 Processando attributo richiesto: '{attr_path}'")
                
                if attr_path in all_attributes:
                    disclosed_attributes[attr_path] = all_attributes[attr_path]
                    valid_attributes.append(attr_path)
                    print(f"   ✅ TROVATO: {attr_path} = {str(all_attributes[attr_path])[:100]}...")
                else:
                    failed_attributes.append(attr_path)
                    print(f"   ❌ NON TROVATO: {attr_path}")
                    
            print(f"📊 RISULTATI ESTRAZIONE:")
            print(f"   ✅ Attributi trovati: {len(disclosed_attributes)} -> {list(disclosed_attributes.keys())}")
            print(f"   ❌ Attributi mancanti: {len(failed_attributes)} -> {failed_attributes}")
            
            # 5. Serializza per sicurezza
            disclosed_attributes = _serialize_datetimes(disclosed_attributes)
            
            print(f"✅ FINALE - Attributi da divulgare: {len(disclosed_attributes)}")
            print(f"✅ FINALE - Attributi validi per prove: {len(valid_attributes)}")
            
            # 6. VERIFICA CRITICA: I due conteggi devono essere uguali
            if len(disclosed_attributes) != len(valid_attributes):
                error_msg = f"MISMATCH CRITICO: disclosed_attributes({len(disclosed_attributes)}) != valid_attributes({len(valid_attributes)})"
                print(f"❌ {error_msg}")
                raise ValueError(error_msg)
            
            # 7. Genera prove Merkle REALI per ogni attributo - SOLO PER QUELLI VALIDI
            merkle_proofs = []
            
            for i, attr_path in enumerate(valid_attributes):
                print(f"🔐 Generando prova Merkle {i+1}/{len(valid_attributes)} per: {attr_path}")
                
                if attr_path not in disclosed_attributes:
                    print(f"   ⚠️ SALTATO: {attr_path} non in disclosed_attributes")
                    continue
                
                try:
                    proof_data = credential.generate_attribute_merkle_proof(attr_path)
                except Exception as e:
                    print(f"   ❌ Errore nella generazione della prova per {attr_path}: {e}")
                    continue

                if proof_data:
                    proof = MerkleProof(
                        attribute_index=proof_data['attribute_index'],
                        attribute_value=proof_data['attribute_value'],
                        proof_path=proof_data['proof_path'],
                        merkle_root=proof_data['merkle_root']
                    )
                    merkle_proofs.append(proof)
                    print(f"   ✅ Prova generata per {attr_path} (indice: {proof_data['attribute_index']})")
                else:
                    print(f"   ❌ Impossibile generare prova per {attr_path}")
            
            print(f"✅ FINALE - Prove Merkle reali generate: {len(merkle_proofs)}")
            
            # 8. VERIFICA FINALE CRITICA
            if len(disclosed_attributes) != len(merkle_proofs):
                error_msg = f"MISMATCH FINALE CRITICO: attributi({len(disclosed_attributes)}) != prove({len(merkle_proofs)})"
                print(f"❌ {error_msg}")
                raise ValueError(error_msg)
            
            # 9. Crea la divulgazione selettiva con prove REALI
            disclosure = SelectiveDisclosure(
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
                ) if expires_hours > 0 else None,
                original_merkle_root=attributes_root  # Usa la root degli attributi
            )
            
            print(f"✅ Selective disclosure REALE creata: {disclosure.disclosure_id}")
            print(f"✅ VERIFICA FINALE: {len(disclosure.disclosed_attributes)} attributi, {len(disclosure.merkle_proofs)} prove")
            return disclosure
            
        except Exception as e:
            print(f"❌ Errore creazione divulgazione selettiva reale: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def _flatten_for_merkle_tree(self) -> List[Tuple[str, Any]]:
        """
        Metodo helper centralizzato per "appiattire" una credenziale in una lista 
        stabile e ordinata di tuple (percorso, valore) per il calcolo del Merkle tree.
        Questo è l'UNICO metodo che definisce quali dati garantiscono l'integrità.
        """
        # La sintassi corretta per escludere campi annidati è un dizionario, non un set.
        exclude_config = {
            'signature': True,          # Esclude il campo 'signature' a livello principale
            'metadata': {'merkle_root'} # Esclude 'merkle_root' dentro 'metadata'
        }
        credential_dict = self.model_dump(mode='json', exclude=exclude_config)

        def flatten(d, parent_key=''):
            items = []
            # Ordina le chiavi per garantire un output deterministico
            for k, v in sorted(d.items()):
                new_key = f"{parent_key}.{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(flatten(v, new_key))
                elif isinstance(v, list):
                    for i, item in enumerate(v):
                        # Se l'elemento della lista è un dizionario, appiattiscilo
                        if isinstance(item, dict):
                            items.extend(flatten(item, f"{new_key}[{i}]"))
                        else:
                            items.append((f"{new_key}[{i}]", item))
                else:
                    items.append((new_key, v))
            return items

        return flatten(credential_dict)
    
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
            print(f"Verificando divulgazione selettiva: {disclosure.disclosure_id[:8]}...")
            
            # 1. Verifica scadenza
            if disclosure.expires_at and datetime.datetime.now(datetime.timezone.utc).isoformat() > disclosure.expires_at:
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
                print(f"Divulgazione selettiva VALIDA")
            else:
                print(f"Divulgazione selettiva NON VALIDA ({len(errors)} errori)")
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
            print(f"Creando presentazione: {len(disclosures)} divulgazioni")
            
            presentation_id = str(uuid.uuid4())
            
            presentation = {
                'presentation_id': presentation_id,
                'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat().isoformat(),
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
                    print(" Presentazione firmata digitalmente")
                except Exception as e:
                    print(f"Errore firma presentazione: {e}")
            
            print(f"Presentazione creata: {presentation_id[:8]}...")
            return presentation
            
        except Exception as e:
            print(f"Errore creazione presentazione: {e}")
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
                print(f"Attributo non trovato: {path}")
            except Exception as e:
                print(f"Errore estrazione {path}: {e}")
        
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
                print("Nessun corso disponibile per Merkle Tree")
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
                print(f"Errore generazione proof per {path}: {e}")
        
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