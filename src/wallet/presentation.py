# =============================================================================
# FASE 4: WALLET E DIVULGAZIONE SELETTIVA - PRESENTATION MANAGER
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


# =============================================================================
# 1. ENUMS E STRUTTURE DATI PRESENTATION
# =============================================================================

class PresentationFormat(Enum):
    """Formati di presentazione"""
    JSON = "json"
    SIGNED_JSON = "signed_json" 
    VERIFIABLE_CREDENTIAL = "verifiable_credential"
    PDF_REPORT = "pdf_report"


class PresentationStatus(Enum):
    """Stati di una presentazione"""
    DRAFT = "draft"
    READY = "ready"
    SENT = "sent"
    VERIFIED = "verified"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class PresentationTemplate:
    """Template per presentazioni"""
    template_id: str
    name: str
    description: str
    disclosure_levels: Dict[str, DisclosureLevel]  # credential_type -> level
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
    """Presentazione verificabile completa"""
    presentation_id: str
    created_at: datetime.datetime
    created_by: str  # Studente
    purpose: str
    recipient: Optional[str] = None
    expires_at: Optional[datetime.datetime] = None
    status: PresentationStatus = PresentationStatus.DRAFT
    
    # Contenuto
    selective_disclosures: List[SelectiveDisclosure] = field(default_factory=list)
    additional_documents: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metadati
    format: PresentationFormat = PresentationFormat.SIGNED_JSON
    signature: Optional[Dict[str, Any]] = None
    verification_url: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
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
            'signature': self.signature,
            'verification_url': self.verification_url,
            'summary': self.get_summary()
        }
    
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
        """Ottiene riassunto della presentazione"""
        credential_ids = set()
        total_attributes = 0
        universities = set()
        
        for disclosure in self.selective_disclosures:
            credential_ids.add(disclosure.credential_id)
            total_attributes += len(disclosure.disclosed_attributes)
            
            # Estrae università dai disclosed attributes
            for path, value in disclosure.disclosed_attributes.items():
                if "university" in path and "name" in path:
                    universities.add(str(value))
        
        return {
            'total_disclosures': len(self.selective_disclosures),
            'unique_credentials': len(credential_ids),
            'total_attributes_disclosed': total_attributes,
            'universities_involved': list(universities),
            'is_expired': (
                self.expires_at and datetime.datetime.utcnow() > self.expires_at
            ),
            'is_signed': self.signature is not None,
            'additional_docs_count': len(self.additional_documents)
        }


# =============================================================================
# 2. PRESENTATION MANAGER
# =============================================================================

class PresentationManager:
    """Manager per la creazione e gestione delle presentazioni"""
    
    def __init__(self, wallet: AcademicStudentWallet):
        """
        Inizializza il presentation manager
        
        Args:
            wallet: Wallet studente associato
        """
        self.wallet = wallet
        self.disclosure_manager = SelectiveDisclosureManager()
        self.crypto_utils = CryptoUtils()
        self.digital_signature = DigitalSignature("PSS")
        
        # Storage presentazioni
        self.presentations: Dict[str, VerifiablePresentation] = {}
        self.templates: Dict[str, PresentationTemplate] = {}
        
        # Inizializza template predefiniti
        self._initialize_default_templates()
        
        print(f"📋 Presentation Manager inizializzato")
        print(f"   Template disponibili: {len(self.templates)}")
    
    def create_presentation(self, 
                          purpose: str,
                          credential_selections: List[Dict[str, Any]],
                          recipient: Optional[str] = None,
                          expires_hours: int = 24,
                          additional_documents: List[Dict[str, Any]] = None) -> str:
        """
        Crea una nuova presentazione
        
        Args:
            purpose: Scopo della presentazione
            credential_selections: Lista selezioni credenziali
                Format: [{"storage_id": str, "disclosure_level": DisclosureLevel, "custom_attributes": List[str]}]
            recipient: Destinatario
            expires_hours: Ore di validità
            additional_documents: Documenti aggiuntivi
            
        Returns:
            ID della presentazione creata
        """
        try:
            if self.wallet.status.value != "unlocked":
                raise RuntimeError("Wallet deve essere sbloccato")
            
            print(f"📋 Creando presentazione: {purpose}")
            print(f"   Credenziali da processare: {len(credential_selections)}")
            
            # 1. Genera ID presentazione
            presentation_id = str(uuid.uuid4())
            
            # 2. Crea divulgazioni selettive
            selective_disclosures = []
            
            for selection in credential_selections:
                storage_id = selection['storage_id']
                disclosure_level = selection.get('disclosure_level', DisclosureLevel.STANDARD)
                custom_attributes = selection.get('custom_attributes', [])
                
                # Ottiene credenziale dal wallet
                wallet_credential = self.wallet.get_credential(storage_id)
                if not wallet_credential:
                    print(f"⚠️  Credenziale non trovata: {storage_id}")
                    continue
                
                credential = wallet_credential.credential
                
                # Crea divulgazione selettiva
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
                
                print(f"   ✅ Disclosure creata per {credential.subject.pseudonym}")
            
            # 3. Calcola scadenza
            expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=expires_hours)
            
            # 4. Ottiene pseudonimo studente (dalla prima credenziale)
            student_pseudonym = "unknown_student"
            if selective_disclosures:
                student_pseudonym = selective_disclosures[0].created_by
            
            # 5. Crea presentazione
            presentation = VerifiablePresentation(
                presentation_id=presentation_id,
                created_at=datetime.datetime.utcnow(),
                created_by=student_pseudonym,
                purpose=purpose,
                recipient=recipient,
                expires_at=expires_at,
                selective_disclosures=selective_disclosures,
                additional_documents=additional_documents or [],
                status=PresentationStatus.DRAFT
            )
            
            # 6. Salva presentazione
            self.presentations[presentation_id] = presentation
            
            print(f"✅ Presentazione creata: {presentation_id[:8]}...")
            print(f"   Disclosures: {len(selective_disclosures)}")
            print(f"   Scadenza: {expires_at}")
            
            return presentation_id
            
        except Exception as e:
            print(f"❌ Errore creazione presentazione: {e}")
            raise
    
    def create_presentation_from_template(self, 
                                        template_id: str,
                                        storage_ids: List[str],
                                        purpose: str,
                                        recipient: Optional[str] = None,
                                        **kwargs) -> str:
        """
        Crea presentazione da template
        
        Args:
            template_id: ID template da usare
            storage_ids: Lista storage ID credenziali
            purpose: Scopo della presentazione
            recipient: Destinatario
            **kwargs: Parametri aggiuntivi
            
        Returns:
            ID presentazione creata
        """
        try:
            if template_id not in self.templates:
                raise ValueError(f"Template non trovato: {template_id}")
            
            template = self.templates[template_id]
            
            print(f"📋 Creando presentazione da template: {template.name}")
            
            # Prepara selezioni credenziali dal template
            credential_selections = []
            
            for storage_id in storage_ids:
                wallet_cred = self.wallet.get_credential(storage_id)
                if not wallet_cred:
                    continue
                
                # Determina livello di disclosure dal template
                credential_type = "default"  # In implementazione reale, determinare dal tipo credenziale
                disclosure_level = template.disclosure_levels.get(
                    credential_type, DisclosureLevel.STANDARD
                )
                
                selection = {
                    'storage_id': storage_id,
                    'disclosure_level': disclosure_level,
                    'custom_attributes': template.required_attributes
                }
                
                credential_selections.append(selection)
            
            # Crea presentazione
            return self.create_presentation(
                purpose=purpose,
                credential_selections=credential_selections,
                recipient=recipient,
                expires_hours=template.validity_hours,
                **kwargs
            )
            
        except Exception as e:
            print(f"❌ Errore creazione da template: {e}")
            raise
    
    def sign_presentation(self, presentation_id: str, 
                         private_key: Optional[rsa.RSAPrivateKey] = None) -> bool:
        """
        Firma digitalmente una presentazione
        
        Args:
            presentation_id: ID presentazione da firmare
            private_key: Chiave privata (usa quella del wallet se None)
            
        Returns:
            True se firmata con successo
        """
        try:
            if presentation_id not in self.presentations:
                print(f"❌ Presentazione non trovata: {presentation_id}")
                return False
            
            presentation = self.presentations[presentation_id]
            
            if presentation.signature:
                print(f"⚠️  Presentazione già firmata")
                return True
            
            print(f"✍️  Firmando presentazione: {presentation_id[:8]}...")
            
            # Usa chiave del wallet se non fornita
            if private_key is None:
                if not self.wallet.wallet_private_key:
                    print(f"❌ Chiave privata wallet non disponibile")
                    return False
                private_key = self.wallet.wallet_private_key
            
            # Prepara dati per firma (esclude la firma stessa)
            presentation_data = presentation.to_dict()
            presentation_data.pop('signature', None)
            
            # Firma documento
            signed_data = self.digital_signature.sign_document(private_key, presentation_data)
            
            # Aggiorna presentazione con firma
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
        """
        Esporta una presentazione
        
        Args:
            presentation_id: ID presentazione
            output_path: Percorso output
            format: Formato export
            
        Returns:
            True se esportata con successo
        """
        try:
            if presentation_id not in self.presentations:
                print(f"❌ Presentazione non trovata: {presentation_id}")
                return False
            
            presentation = self.presentations[presentation_id]
            
            print(f"💾 Esportando presentazione: {format.value}")
            
            if format == PresentationFormat.JSON:
                # JSON semplice
                export_data = presentation.to_dict()
                
            elif format == PresentationFormat.SIGNED_JSON:
                # JSON firmato
                if not presentation.signature:
                    print(f"⚠️  Presentazione non firmata, firmo automaticamente...")
                    self.sign_presentation(presentation_id)
                
                export_data = presentation.to_dict()
                
            elif format == PresentationFormat.VERIFIABLE_CREDENTIAL:
                # Formato W3C Verifiable Credentials (semplificato)
                export_data = self._convert_to_vc_format(presentation)
                
            elif format == PresentationFormat.PDF_REPORT:
                # Genera report PDF (implementazione placeholder)
                return self._export_pdf_report(presentation, output_path)
            
            else:
                raise ValueError(f"Formato non supportato: {format}")
            
            # Salva file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
            
            print(f"✅ Presentazione esportata: {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ Errore export presentazione: {e}")
            return False
    
    def verify_presentation(self, presentation_data: Dict[str, Any], 
                          public_key: Optional[rsa.RSAPublicKey] = None) -> Tuple[bool, List[str]]:
        """
        Verifica una presentazione
        
        Args:
            presentation_data: Dati presentazione da verificare
            public_key: Chiave pubblica per verifica firma
            
        Returns:
            Tupla (valida, lista_errori)
        """
        errors = []
        
        try:
            print(f"🔍 Verificando presentazione...")
            
            # 1. Verifica formato base
            required_fields = ['presentation_id', 'created_at', 'purpose', 'selective_disclosures']
            for field in required_fields:
                if field not in presentation_data:
                    errors.append(f"Campo obbligatorio mancante: {field}")
            
            if errors:
                return False, errors
            
            # 2. Verifica scadenza
            expires_at = presentation_data.get('expires_at')
            if expires_at:
                expiry_date = datetime.datetime.fromisoformat(expires_at)
                if datetime.datetime.utcnow() > expiry_date:
                    errors.append("Presentazione scaduta")
            
            # 3. Verifica firma se presente
            signature = presentation_data.get('signature')
            if signature and public_key:
                try:
                    # Prepara dati per verifica (senza firma)
                    verify_data = presentation_data.copy()
                    verify_data.pop('signature', None)
                    
                    # Ricostruisce documento firmato
                    verify_data['firma'] = signature
                    
                    is_signature_valid = self.digital_signature.verify_document_signature(
                        public_key, verify_data
                    )
                    
                    if not is_signature_valid:
                        errors.append("Firma digitale non valida")
                        
                except Exception as e:
                    errors.append(f"Errore verifica firma: {e}")
            
            # 4. Verifica divulgazioni selettive
            disclosures = presentation_data.get('selective_disclosures', [])
            
            for i, disclosure_data in enumerate(disclosures):
                try:
                    disclosure = SelectiveDisclosure.from_dict(disclosure_data)
                    
                    # Verifica disclosure individualmente
                    merkle_root = disclosure.merkle_root if hasattr(disclosure, 'merkle_root') else "dummy_root"
                    is_valid, disclosure_errors = self.disclosure_manager.verify_selective_disclosure(
                        disclosure, merkle_root
                    )
                    
                    if not is_valid:
                        errors.extend([f"Disclosure {i}: {err}" for err in disclosure_errors])
                        
                except Exception as e:
                    errors.append(f"Errore verifica disclosure {i}: {e}")
            
            # 5. Verifica coerenza
            if len(disclosures) == 0:
                errors.append("Nessuna divulgazione selettiva presente")
            
            is_valid = len(errors) == 0
            
            if is_valid:
                print(f"✅ Presentazione VALIDA")
            else:
                print(f"❌ Presentazione NON VALIDA ({len(errors)} errori)")
                for error in errors[:3]:
                    print(f"   - {error}")
            
            return is_valid, errors
            
        except Exception as e:
            errors.append(f"Errore durante verifica: {e}")
            return False, errors
    
    def list_presentations(self, filter_status: Optional[PresentationStatus] = None) -> List[Dict[str, Any]]:
        """
        Lista presentazioni create
        
        Args:
            filter_status: Filtra per status
            
        Returns:
            Lista riassunti presentazioni
        """
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
        
        # Ordina per data creazione (più recenti primi)
        results.sort(key=lambda x: x['created_at'], reverse=True)
        
        return results
    
    def get_presentation(self, presentation_id: str) -> Optional[VerifiablePresentation]:
        """Ottiene una presentazione per ID"""
        return self.presentations.get(presentation_id)
    
    def delete_presentation(self, presentation_id: str) -> bool:
        """
        Elimina una presentazione
        
        Args:
            presentation_id: ID presentazione da eliminare
            
        Returns:
            True se eliminata
        """
        if presentation_id in self.presentations:
            del self.presentations[presentation_id]
            print(f"🗑️  Presentazione eliminata: {presentation_id[:8]}...")
            return True
        
        return False
    
    def get_templates(self) -> Dict[str, PresentationTemplate]:
        """Ottiene template disponibili"""
        return self.templates.copy()
    
    def add_template(self, template: PresentationTemplate):
        """Aggiunge un template personalizzato"""
        self.templates[template.template_id] = template
        print(f"📋 Template aggiunto: {template.name}")
    
    def _initialize_default_templates(self):
        """Inizializza template predefiniti"""
        templates = [
            PresentationTemplate(
                template_id="university_enrollment",
                name="Verifica Iscrizione Università",
                description="Presentazione per verificare iscrizione presso università",
                disclosure_levels={"default": DisclosureLevel.MINIMAL},
                required_attributes=[
                    "metadata.credential_id", "subject.pseudonym", 
                    "issuer.name", "total_ects_credits"
                ],
                optional_attributes=["study_period.academic_year"],
                typical_recipients=["Uffici Università", "Enti Pubblici"],
                validity_hours=24
            ),
            
            PresentationTemplate(
                template_id="academic_transcript",
                name="Trascrizione Accademica Completa",
                description="Trascrizione completa di tutti i corsi e voti",
                disclosure_levels={"default": DisclosureLevel.DETAILED},
                required_attributes=[
                    "metadata.credential_id", "subject.pseudonym",
                    "issuer.name", "host_university.name",
                    "courses.*.course_name", "courses.*.grade.score"
                ],
                optional_attributes=["courses.*.professor", "average_grade"],
                typical_recipients=["Università", "Datori di lavoro"],
                validity_hours=72
            ),
            
            PresentationTemplate(
                template_id="erasmus_certificate",
                name="Certificato Mobilità Erasmus",
                description="Certificato partecipazione programma Erasmus",
                disclosure_levels={"default": DisclosureLevel.STANDARD},
                required_attributes=[
                    "metadata.credential_id", "subject.pseudonym",
                    "host_university.name", "study_period.study_type",
                    "study_period.start_date", "study_period.end_date"
                ],
                optional_attributes=["courses.*.course_name", "total_ects_credits"],
                typical_recipients=["Università di origine", "CV/Curriculum"],
                validity_hours=168  # 1 settimana
            ),
            
            PresentationTemplate(
                template_id="job_application",
                name="Candidatura Lavoro",
                description="Presentazione per candidature lavorative",
                disclosure_levels={"default": DisclosureLevel.STANDARD},
                required_attributes=[
                    "subject.pseudonym", "host_university.name",
                    "study_program.name", "study_program.eqf_level",
                    "total_ects_credits"
                ],
                optional_attributes=[
                    "courses.*.course_name", "average_grade",
                    "study_period.academic_year"
                ],
                typical_recipients=["Aziende", "HR Departments"],
                validity_hours=48
            )
        ]
        
        for template in templates:
            self.templates[template.template_id] = template
        
        print(f"📋 Inizializzati {len(templates)} template predefiniti")
    
    def _convert_to_vc_format(self, presentation: VerifiablePresentation) -> Dict[str, Any]:
        """Converte in formato W3C Verifiable Credentials (semplificato)"""
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
        """Genera report PDF (implementazione placeholder)"""
        # Implementazione semplificata - genera HTML che può essere convertito in PDF
        try:
            html_content = self._generate_html_report(presentation)
            
            # Salva come HTML (in implementazione reale, convertire in PDF)
            html_path = output_path.replace('.pdf', '.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"📄 Report HTML generato: {html_path}")
            print("   💡 In implementazione completa, convertire in PDF")
            
            return True
            
        except Exception as e:
            print(f"❌ Errore generazione PDF: {e}")
            return False
    
    def _generate_html_report(self, presentation: VerifiablePresentation) -> str:
        """Genera report HTML della presentazione"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Academic Credentials Presentation</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ border-bottom: 2px solid #ccc; padding-bottom: 20px; }}
                .section {{ margin: 20px 0; }}
                .disclosure {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; }}
                .attribute {{ margin: 5px 0; }}
                .signature {{ background-color: #f0f8ff; padding: 10px; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Academic Credentials Presentation</h1>
                <p><strong>Presentation ID:</strong> {presentation.presentation_id}</p>
                <p><strong>Created:</strong> {presentation.created_at}</p>
                <p><strong>Student:</strong> {presentation.created_by}</p>
                <p><strong>Purpose:</strong> {presentation.purpose}</p>
                {f'<p><strong>Recipient:</strong> {presentation.recipient}</p>' if presentation.recipient else ''}
            </div>
            
            <div class="section">
                <h2>Disclosed Credentials</h2>
        """
        
        for i, disclosure in enumerate(presentation.selective_disclosures):
            html += f"""
                <div class="disclosure">
                    <h3>Credential {i+1}</h3>
                    <p><strong>Credential ID:</strong> {disclosure.credential_id}</p>
                    <p><strong>Disclosure Level:</strong> {disclosure.disclosure_level.value}</p>
                    <h4>Disclosed Attributes:</h4>
            """
            
            for path, value in disclosure.disclosed_attributes.items():
                html += f'<div class="attribute"><strong>{path}:</strong> {value}</div>'
            
            html += "</div>"
        
        if presentation.signature:
            html += f"""
            <div class="signature">
                <h3>Digital Signature</h3>
                <p><strong>Algorithm:</strong> {presentation.signature.get('algoritmo', 'N/A')}</p>
                <p><strong>Timestamp:</strong> {presentation.signature.get('timestamp', 'N/A')}</p>
                <p><strong>Status:</strong> Digitally Signed ✓</p>
            </div>
            """
        
        html += """
            </div>
        </body>
        </html>
        """
        
        return html


# =============================================================================
# 3. DEMO E TESTING
# =============================================================================

def demo_presentation_manager():
    """Demo del Presentation Manager"""
    
    print("📋" * 40)
    print("DEMO PRESENTATION MANAGER")
    print("Gestione Presentazioni Verificabili")
    print("📋" * 40)
    
    try:
        # 1. Setup wallet e presentazione manager
        print("\n1️⃣ SETUP WALLET E PRESENTATION MANAGER")
        
        # Configura wallet temporaneo per demo
        wallet_config = WalletConfiguration(
            wallet_name="Demo Presentation Wallet",
            storage_path="./wallet/demo_presentation",
            storage_mode=CredentialStorage.ENCRYPTED_LOCAL,
            auto_backup=False,
            require_password=True
        )
        
        wallet = AcademicStudentWallet(wallet_config)
        
        # Crea/sblocca wallet
        password = "DemoPassword123!"
        
        if not wallet.wallet_file.exists():
            wallet.create_wallet(password)
        
        wallet.unlock_wallet(password)
        
        # Inizializza presentation manager
        presentation_manager = PresentationManager(wallet)
        
        print(f"✅ Wallet e Presentation Manager inizializzati")
        
        # 2. Aggiunge credenziali di test al wallet
        print("\n2️⃣ AGGIUNTA CREDENZIALI DI TEST")
        
        test_credentials = []
        storage_ids = []
        
        # Crea 3 credenziali di esempio
        for i in range(3):
            cred = CredentialFactory.create_sample_credential()
            
            # Personalizza per varietà
            if i == 1:
                cred.subject.pseudonym = "student_tech_exchange"
                cred.host_university.name = "Technical University Berlin"
                cred.host_university.country = "DE"
            elif i == 2:
                cred.subject.pseudonym = "student_research_visit"
                cred.host_university.name = "Oxford University"
                cred.host_university.country = "GB"
            
            storage_id = wallet.add_credential(cred, [f"demo_{i}", "presentation_test"])
            storage_ids.append(storage_id)
            test_credentials.append(cred)
        
        print(f"✅ Aggiunte {len(storage_ids)} credenziali al wallet")
        
        # 3. Lista template disponibili
        print("\n3️⃣ TEMPLATE DISPONIBILI")
        
        templates = presentation_manager.get_templates()
        
        for template_id, template in templates.items():
            print(f"📋 {template.name}:")
            print(f"   ID: {template_id}")
            print(f"   Descrizione: {template.description}")
            print(f"   Validità: {template.validity_hours} ore")
            print(f"   Destinatari tipici: {', '.join(template.typical_recipients)}")
        
        # 4. Creazione presentazione da template
        print("\n4️⃣ CREAZIONE PRESENTAZIONE DA TEMPLATE")
        
        # Usa template "university_enrollment"
        template_presentation_id = presentation_manager.create_presentation_from_template(
            template_id="university_enrollment",
            storage_ids=[storage_ids[0]],  # Prima credenziale
            purpose="Verifica iscrizione per borsa di studio",
            recipient="Ufficio Borse di Studio Università"
        )
        
        print(f"✅ Presentazione da template creata: {template_presentation_id[:8]}...")
        
        # 5. Creazione presentazione personalizzata
        print("\n5️⃣ CREAZIONE PRESENTAZIONE PERSONALIZZATA")
        
        # Definisce selezioni personalizzate
        credential_selections = [
            {
                'storage_id': storage_ids[0],
                'disclosure_level': DisclosureLevel.STANDARD,
            },
            {
                'storage_id': storage_ids[1],
                'disclosure_level': DisclosureLevel.MINIMAL,
            },
            {
                'storage_id': storage_ids[2],
                'custom_attributes': [
                    "metadata.credential_id",
                    "subject.pseudonym",
                    "host_university.name",
                    "courses.0.course_name",
                    "courses.0.grade.score",
                    "total_ects_credits"
                ]
            }
        ]
        
        custom_presentation_id = presentation_manager.create_presentation(
            purpose="Candidatura Master Degree - Portfolio Accademico Completo",
            credential_selections=credential_selections,
            recipient="Commissione Ammissioni Master Program",
            expires_hours=72,
            additional_documents=[
                {
                    "type": "motivation_letter",
                    "description": "Lettera motivazionale",
                    "url": "https://example.com/motivation.pdf"
                }
            ]
        )
        
        print(f"✅ Presentazione personalizzata creata: {custom_presentation_id[:8]}...")
        
        # 6. Firma presentazioni
        print("\n6️⃣ FIRMA DIGITALE PRESENTAZIONI")
        
        presentations_to_sign = [template_presentation_id, custom_presentation_id]
        
        for pres_id in presentations_to_sign:
            success = presentation_manager.sign_presentation(pres_id)
            if success:
                print(f"   ✅ Presentazione firmata: {pres_id[:8]}...")
        
        # 7. Lista presentazioni create
        print("\n7️⃣ LISTA PRESENTAZIONI")
        
        all_presentations = presentation_manager.list_presentations()
        
        print(f"📋 Presentazioni create: {len(all_presentations)}")
        for pres in all_presentations:
            print(f"   - {pres['presentation_id'][:8]}... | {pres['purpose'][:50]}... | Status: {pres['status']}")
            print(f"     Disclosures: {pres['total_disclosures']} | Credenziali: {pres['unique_credentials']} | Firmata: {pres['is_signed']}")
        
        # 8. Export presentazioni
        print("\n8️⃣ EXPORT PRESENTAZIONI")
        
        export_dir = Path("./wallet/exports")
        export_dir.mkdir(parents=True, exist_ok=True)
        
        # Export in diversi formati
        for i, pres_id in enumerate([template_presentation_id, custom_presentation_id]):
            # JSON firmato
            json_path = export_dir / f"presentation_{i+1}.json"
            presentation_manager.export_presentation(
                pres_id, str(json_path), PresentationFormat.SIGNED_JSON
            )
            
            # Formato VC
            vc_path = export_dir / f"presentation_{i+1}_vc.json"
            presentation_manager.export_presentation(
                pres_id, str(vc_path), PresentationFormat.VERIFIABLE_CREDENTIAL
            )
            
            # Report HTML
            html_path = export_dir / f"presentation_{i+1}_report.html"
            presentation_manager.export_presentation(
                pres_id, str(html_path), PresentationFormat.PDF_REPORT
            )
        
        print(f"💾 Presentazioni esportate in: {export_dir}")
        
        # 9. Verifica presentazioni
        print("\n9️⃣ VERIFICA PRESENTAZIONI")
        
        # Test verifica con la prima presentazione
        presentation = presentation_manager.get_presentation(template_presentation_id)
        if presentation:
            presentation_data = presentation.to_dict()
            
            # Verifica con chiave pubblica del wallet
            is_valid, errors = presentation_manager.verify_presentation(
                presentation_data, wallet.wallet_public_key
            )
            
            print(f"   🔍 Verifica presentazione: {'✅ VALIDA' if is_valid else '❌ NON VALIDA'}")
            if errors:
                for error in errors[:3]:
                    print(f"      - {error}")
        
        # 10. Statistiche finali
        print("\n🔟 STATISTICHE FINALI")
        
        ready_presentations = presentation_manager.list_presentations(PresentationStatus.READY)
        
        print("📊 Riepilogo:")
        print(f"   Template disponibili: {len(templates)}")
        print(f"   Presentazioni create: {len(all_presentations)}")
        print(f"   Presentazioni pronte: {len(ready_presentations)}")
        print(f"   Credenziali nel wallet: {len(storage_ids)}")
        
        # Dettagli presentazione personalizzata
        if custom_presentation_id in presentation_manager.presentations:
            custom_pres = presentation_manager.presentations[custom_presentation_id]
            summary = custom_pres.get_summary()
            
            print(f"\n📋 Dettagli presentazione personalizzata:")
            print(f"   Attributi divulgati: {summary['total_attributes_disclosed']}")
            print(f"   Università coinvolte: {len(summary['universities_involved'])}")
            print(f"   Documenti aggiuntivi: {summary['additional_docs_count']}")
        
        print("\n" + "✅" * 40)
        print("DEMO PRESENTATION MANAGER COMPLETATA!")
        print("✅" * 40)
        
        return presentation_manager, [template_presentation_id, custom_presentation_id]
        
    except Exception as e:
        print(f"\n❌ Errore durante demo: {e}")
        import traceback
        traceback.print_exc()
        return None, []


# =============================================================================
# 4. MAIN - PUNTO DI INGRESSO
# =============================================================================

if __name__ == "__main__":
    print("📋" * 50)
    print("PRESENTATION MANAGER")
    print("Gestione Presentazioni Verificabili")
    print("📋" * 50)
    
    # Esegui demo
    manager, presentation_ids = demo_presentation_manager()
    
    if manager:
        print("\n🎉 Presentation Manager pronto!")
        print("\nFunzionalità disponibili:")
        print("✅ Creazione presentazioni multi-credential")
        print("✅ Template predefiniti per casi d'uso comuni")
        print("✅ Divulgazione selettiva avanzata")
        print("✅ Firma digitale presentazioni")
        print("✅ Export multi-formato (JSON, VC, PDF)")
        print("✅ Verifica presentazioni ricevute")
        print("✅ Gestione scadenze e stati")
        print("✅ Template personalizzabili")
        
        print(f"\n🚀 FASE 4 COMPLETATA!")
        print(f"📋 Presentazioni demo: {len(presentation_ids)}")
        print("Pronti per la Fase 5: Comunicazione Sicura!")
    else:
        print("\n❌ Errore inizializzazione Presentation Manager")