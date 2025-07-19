# =============================================================================
# FASE 4: WALLET E DIVULGAZIONE SELETTIVA - PRESENTATION MANAGER (CORRETTO)
# File: wallet/presentation.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import json
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import uuid

# Cryptography imports
from cryptography.hazmat.primitives.asymmetric import rsa

# Import moduli interni
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from crypto.foundations import DigitalSignature, CryptoUtils
    from credentials.models import AcademicCredential, CredentialFactory
    from wallet.student_wallet import AcademicStudentWallet, WalletConfiguration, CredentialStorage
    from wallet.selective_disclosure import (
        SelectiveDisclosureManager, SelectiveDisclosure, DisclosureLevel
    )
except ImportError as e:
    print(f"⚠️  Errore import moduli interni: {e}")
    print("   Assicurati che tutti i moduli siano presenti nel progetto")
    raise


# ... (TUTTO IL CODICE PRECEDENTE FINO A sign_presentation RIMANE INVARIATO) ...
# (Le classi PresentationFormat, PresentationStatus, PresentationTemplate, VerifiablePresentation rimangono le stesse)

class PresentationFormat(Enum):
    JSON = "json"
    SIGNED_JSON = "signed_json" 
    VERIFIABLE_CREDENTIAL = "verifiable_credential"
    PDF_REPORT = "pdf_report"

class PresentationStatus(Enum):
    DRAFT = "draft"
    READY = "ready"
    SENT = "sent"
    VERIFIED = "verified"
    EXPIRED = "expired"
    REVOKED = "revoked"

@dataclass
class PresentationTemplate:
    template_id: str
    name: str
    description: str
    disclosure_levels: Dict[str, DisclosureLevel]
    required_attributes: List[str]
    optional_attributes: List[str]
    typical_recipients: List[str]
    validity_hours: int = 24
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'template_id': self.template_id,
            'name': self.name,
            'description': self.description,
            'disclosure_levels': {k: v.value for k, v in self.disclosure_levels.items()},
            'required_attributes': self.required_attributes,
            'optional_attributes': self.optional_attributes,
            'typical_recipients': self.typical_recipients,
            'validity_hours': self.validity_hours
        }

@dataclass
class VerifiablePresentation:
    presentation_id: str
    created_at: datetime.datetime
    created_by: str
    purpose: str
    recipient: Optional[str] = None
    expires_at: Optional[datetime.datetime] = None
    status: PresentationStatus = PresentationStatus.DRAFT
    selective_disclosures: List[SelectiveDisclosure] = field(default_factory=list)
    additional_documents: List[Dict[str, Any]] = field(default_factory=list)
    format: PresentationFormat = PresentationFormat.SIGNED_JSON
    signature: Optional[Dict[str, Any]] = None
    verification_url: Optional[str] = None
    
    def get_data_for_signing(self) -> Dict[str, Any]:
        """Restituisce solo i dati essenziali da firmare, escludendo campi dinamici."""
        return {
            'presentation_id': self.presentation_id,
            'created_at': self.created_at.isoformat(),
            'created_by': self.created_by,
            'purpose': self.purpose,
            'recipient': self.recipient,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'status': self.status.value,
            'selective_disclosures': [sd.to_dict() for sd in self.selective_disclosures],
            'additional_documents': self.additional_documents,
            'format': self.format.value,
            'verification_url': self.verification_url,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Converte l'intera presentazione in dizionario, includendo il sommario."""
        data = self.get_data_for_signing()
        data['signature'] = self.signature
        data['summary'] = self.get_summary()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VerifiablePresentation':
        return cls(
            presentation_id=data['presentation_id'],
            created_at=datetime.datetime.fromisoformat(data['created_at']),
            created_by=data['created_by'],
            purpose=data['purpose'],
            recipient=data.get('recipient'),
            expires_at=(
                datetime.datetime.fromisoformat(data['expires_at'])
                if data.get('expires_at') else None
            ),
            status=PresentationStatus(data['status']),
            selective_disclosures=[
                SelectiveDisclosure.from_dict(sd) for sd in data['selective_disclosures']
            ],
            additional_documents=data.get('additional_documents', []),
            format=PresentationFormat(data['format']),
            signature=data.get('signature'),
            verification_url=data.get('verification_url')
        )
    
    def get_summary(self) -> Dict[str, Any]:
        credential_ids = set()
        total_attributes = 0
        universities = set()
        
        for disclosure in self.selective_disclosures:
            credential_ids.add(disclosure.credential_id)
            total_attributes += len(disclosure.disclosed_attributes)
            for path, value in disclosure.disclosed_attributes.items():
                if "university" in path and "name" in path:
                    universities.add(str(value))
        
        return {
            'total_disclosures': len(self.selective_disclosures),
            'unique_credentials': len(credential_ids),
            'total_attributes_disclosed': total_attributes,
            'universities_involved': list(universities),
            'is_expired': (
                self.expires_at and datetime.datetime.now(datetime.timezone.utc) > self.expires_at
            ),
            'is_signed': self.signature is not None,
            'additional_docs_count': len(self.additional_documents)
        }

class PresentationManager:
    """Manager per la creazione e gestione delle presentazioni"""
    
    def __init__(self, wallet: AcademicStudentWallet):
        self.wallet = wallet
        self.disclosure_manager = SelectiveDisclosureManager()
        self.crypto_utils = CryptoUtils()
        self.digital_signature = DigitalSignature("PSS")
        self.presentations: Dict[str, VerifiablePresentation] = {}
        self.templates: Dict[str, PresentationTemplate] = {}
        self._initialize_default_templates()
        print(f"📋 Presentation Manager inizializzato")
        print(f"   Template disponibili: {len(self.templates)}")
    
    def create_presentation(self, 
                          purpose: str,
                          credential_selections: List[Dict[str, Any]],
                          recipient: Optional[str] = None,
                          expires_hours: int = 24,
                          additional_documents: List[Dict[str, Any]] = None) -> str:
        try:
            if self.wallet.status.value != "unlocked":
                raise RuntimeError("Wallet deve essere sbloccato")
            
            presentation_id = str(uuid.uuid4())
            selective_disclosures = []
            
            for selection in credential_selections:
                storage_id = selection['storage_id']
                disclosure_level = selection.get('disclosure_level', DisclosureLevel.STANDARD)
                custom_attributes = selection.get('custom_attributes', [])
                wallet_credential = self.wallet.get_credential(storage_id)
                if not wallet_credential:
                    continue
                credential = wallet_credential.credential
                
                if custom_attributes:
                    disclosure = self.disclosure_manager.create_selective_disclosure(
                        credential, custom_attributes, DisclosureLevel.CUSTOM,
                        purpose=purpose, recipient=recipient, expires_hours=expires_hours
                    )
                else:
                    disclosure = self.disclosure_manager.create_predefined_disclosure(
                        credential, disclosure_level,
                        purpose=purpose, recipient=recipient, expires_hours=expires_hours
                    )
                selective_disclosures.append(disclosure)
            
            expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=expires_hours)
            student_pseudonym = "unknown_student"
            if selective_disclosures:
                student_pseudonym = selective_disclosures[0].created_by
            
            presentation = VerifiablePresentation(
                presentation_id=presentation_id,
                created_at=datetime.datetime.now(datetime.timezone.utc),
                created_by=student_pseudonym,
                purpose=purpose,
                recipient=recipient,
                expires_at=expires_at,
                selective_disclosures=selective_disclosures,
                additional_documents=additional_documents or [],
                status=PresentationStatus.DRAFT
            )
            
            self.presentations[presentation_id] = presentation
            return presentation_id
            
        except Exception as e:
            raise
    
    def create_presentation_from_template(self, 
                                        template_id: str,
                                        storage_ids: List[str],
                                        purpose: str,
                                        recipient: Optional[str] = None,
                                        **kwargs) -> str:
        # (Questo metodo rimane invariato)
        try:
            if template_id not in self.templates:
                raise ValueError(f"Template non trovato: {template_id}")
            
            template = self.templates[template_id]
            credential_selections = []
            
            for storage_id in storage_ids:
                wallet_cred = self.wallet.get_credential(storage_id)
                if not wallet_cred:
                    continue
                credential_type = "default"
                disclosure_level = template.disclosure_levels.get(
                    credential_type, DisclosureLevel.STANDARD
                )
                selection = {
                    'storage_id': storage_id,
                    'disclosure_level': disclosure_level,
                    'custom_attributes': template.required_attributes
                }
                credential_selections.append(selection)
            
            return self.create_presentation(
                purpose=purpose,
                credential_selections=credential_selections,
                recipient=recipient,
                expires_hours=template.validity_hours,
                **kwargs
            )
        except Exception as e:
            raise

    def sign_presentation(self, presentation_id: str, 
                         private_key: Optional[rsa.RSAPrivateKey] = None) -> bool:
        """Firma digitalmente una presentazione usando solo i dati essenziali."""
        try:
            if presentation_id not in self.presentations:
                return False
            
            presentation = self.presentations[presentation_id]
            if presentation.signature:
                return True
            
            if private_key is None:
                if not self.wallet.wallet_private_key:
                    return False
                private_key = self.wallet.wallet_private_key
            
            presentation_data_to_sign = presentation.get_data_for_signing()
            
            # Firma il documento essenziale
            signed_data = self.digital_signature.sign_document(private_key, presentation_data_to_sign)
            
            # Aggiorna la presentazione con la firma
            presentation.signature = signed_data.get('firma')
            presentation.status = PresentationStatus.READY
            
            print(f"✅ Presentazione firmata con successo")
            return True
            
        except Exception as e:
            print(f"❌ Errore firma presentazione: {e}")
            return False

    def export_presentation(self, presentation_id: str, 
                          output_path: str,
                          format: PresentationFormat = PresentationFormat.SIGNED_JSON) -> bool:
        try:
            if presentation_id not in self.presentations:
                return False
            
            presentation = self.presentations[presentation_id]
            
            if format == PresentationFormat.JSON:
                export_data = presentation.to_dict()
            elif format == PresentationFormat.SIGNED_JSON:
                if not presentation.signature:
                    self.sign_presentation(presentation_id)
                export_data = presentation.to_dict()
            elif format == PresentationFormat.VERIFIABLE_CREDENTIAL:
                export_data = self._convert_to_vc_format(presentation)
            elif format == PresentationFormat.PDF_REPORT:
                return self._export_pdf_report(presentation, output_path)
            else:
                raise ValueError(f"Formato non supportato: {format}")
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
            
            return True
        except Exception as e:
            # Aggiungiamo una stampa dettagliata dell'errore nel terminale
            print(f"❌ ERRORE CRITICO in export_presentation: {e}")
            import traceback
            traceback.print_exc()
            return False


# ... (Il resto del file `presentation.py` rimane invariato) ...
    def verify_presentation(self, presentation_data: Dict[str, Any], 
                          public_key: Optional[rsa.RSAPublicKey] = None) -> Tuple[bool, List[str]]:
        errors = []
        try:
            required_fields = ['presentation_id', 'created_at', 'purpose', 'selective_disclosures']
            for field in required_fields:
                if field not in presentation_data:
                    errors.append(f"Campo obbligatorio mancante: {field}")
            if errors:
                return False, errors
            
            expires_at = presentation_data.get('expires_at')
            if expires_at:
                expiry_date = datetime.datetime.fromisoformat(expires_at)
                if datetime.datetime.utcnow() > expiry_date:
                    errors.append("Presentazione scaduta")
            
            signature = presentation_data.get('signature')
            if signature and public_key:
                try:
                    # **MODIFICA**: Ricostruiamo i dati per la verifica escludendo summary
                    data_for_verification = presentation_data.copy()
                    data_for_verification.pop('signature', None)
                    data_for_verification.pop('summary', None) # Rimuoviamo il summary
                    
                    data_for_verification['firma'] = signature
                    
                    is_signature_valid = self.digital_signature.verify_document_signature(
                        public_key, data_for_verification
                    )
                    
                    if not is_signature_valid:
                        errors.append("Firma digitale non valida")
                except Exception as e:
                    errors.append(f"Errore verifica firma: {e}")

            disclosures = presentation_data.get('selective_disclosures', [])
            for i, disclosure_data in enumerate(disclosures):
                try:
                    disclosure = SelectiveDisclosure.from_dict(disclosure_data)
                    merkle_root = "dummy_root" # Semplificazione per la demo
                    is_valid, disclosure_errors = self.disclosure_manager.verify_selective_disclosure(
                        disclosure, merkle_root
                    )
                    if not is_valid:
                        errors.extend([f"Disclosure {i}: {err}" for err in disclosure_errors])
                except Exception as e:
                    errors.append(f"Errore verifica disclosure {i}: {e}")
            
            if len(disclosures) == 0:
                errors.append("Nessuna divulgazione selettiva presente")
            
            return len(errors) == 0, errors
        except Exception as e:
            errors.append(f"Errore durante verifica: {e}")
            return False, errors

    def list_presentations(self, filter_status: Optional[PresentationStatus] = None) -> List[Dict[str, Any]]:
        results = []
        for presentation in self.presentations.values():
            if filter_status and presentation.status != filter_status:
                continue
            summary = presentation.get_summary()
            summary.update({
                'presentation_id': presentation.presentation_id,
                'created_at': presentation.created_at.isoformat(),
                'purpose': presentation.purpose,
                'recipient': presentation.recipient,
                'status': presentation.status.value,
                'expires_at': presentation.expires_at.isoformat() if presentation.expires_at else None
            })
            results.append(summary)
        results.sort(key=lambda x: x['created_at'], reverse=True)
        return results
    
    def get_presentation(self, presentation_id: str) -> Optional[VerifiablePresentation]:
        return self.presentations.get(presentation_id)
    
    def delete_presentation(self, presentation_id: str) -> bool:
        if presentation_id in self.presentations:
            del self.presentations[presentation_id]
            return True
        return False
    
    def get_templates(self) -> Dict[str, PresentationTemplate]:
        return self.templates.copy()
    
    def add_template(self, template: PresentationTemplate):
        self.templates[template.template_id] = template
    
    def _initialize_default_templates(self):
        templates = [
            PresentationTemplate(
                template_id="university_enrollment",
                name="Verifica Iscrizione Università",
                description="Presentazione per verificare iscrizione presso università",
                disclosure_levels={"default": DisclosureLevel.MINIMAL},
                required_attributes=["metadata.credential_id", "subject.pseudonym", "issuer.name", "total_ects_credits"],
                optional_attributes=["study_period.academic_year"],
                typical_recipients=["Uffici Università"],
                validity_hours=24
            ),
        ]
        for template in templates:
            self.templates[template.template_id] = template

    def _convert_to_vc_format(self, presentation: VerifiablePresentation) -> Dict[str, Any]:
        return {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "id": f"urn:presentation:{presentation.presentation_id}",
            "holder": presentation.created_by,
            "verifiableCredential": [
                {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential", "AcademicCredential"],
                    "credentialSubject": disclosure.disclosed_attributes,
                    "proof": {
                        "type": "MerkleProof2021",
                        "merkleRoot": disclosure.merkle_proofs[0].merkle_root if disclosure.merkle_proofs else None,
                        "proofPath": disclosure.merkle_proofs[0].proof_path if disclosure.merkle_proofs else []
                    }
                }
                for disclosure in presentation.selective_disclosures
            ],
            "proof": presentation.signature
        }
    
    def _export_pdf_report(self, presentation: VerifiablePresentation, output_path: str) -> bool:
        try:
            html_content = self._generate_html_report(presentation)
            html_path = output_path.replace('.pdf', '.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return True
        except Exception as e:
            return False
    
    def _generate_html_report(self, presentation: VerifiablePresentation) -> str:
        # Funzione helper per generare un semplice report HTML
        # (L'implementazione non è cambiata)
        html = f"""
        <!DOCTYPE html><html><head><title>Presentation</title></head><body>
        <h1>Presentation: {presentation.presentation_id}</h1>
        <p>Purpose: {presentation.purpose}</p>
        </body></html>
        """
        return html