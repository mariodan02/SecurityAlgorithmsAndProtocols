# =============================================================================
# FASE 3: STRUTTURA CREDENZIALI ACCADEMICHE - MODELS (AGGIORNATO A Pydantic V2)
# File: credentials/models.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import json
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import uuid

# Pydantic per validazione dati
# MODIFICA: Import dei nuovi decoratori da Pydantic V2
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic.types import UUID4

# Import moduli interni
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    # Assumiamo che CryptoUtils e MerkleTree siano definiti in crypto.foundations
    # In un progetto reale, questo sarebbe un pacchetto installabile.
    from crypto.foundations import CryptoUtils, MerkleTree
except ImportError:
    print("⚠️  Assicurati che i moduli crypto (CryptoUtils, MerkleTree) siano disponibili.")

# =============================================================================
# 1. ENUMS E COSTANTI
# =============================================================================

class CredentialStatus(Enum):
    """Stati possibili di una credenziale"""
    DRAFT = "draft"
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    SUSPENDED = "suspended"


class StudyType(Enum):
    """Tipologie di studio"""
    ERASMUS = "erasmus"
    EXCHANGE = "exchange"
    DOUBLE_DEGREE = "double_degree"
    REGULAR = "regular"


class GradeSystem(Enum):
    """Sistemi di voti"""
    ITALIAN_30 = "italian_30"
    FRENCH_20 = "french_20"
    GERMAN_6 = "german_6"
    ECTS_GRADE = "ects_grade"
    US_GPA = "us_gpa"


class EQFLevel(Enum):
    """European Qualifications Framework Levels"""
    LEVEL_6 = "6"
    LEVEL_7 = "7"
    LEVEL_8 = "8"


# =============================================================================
# 2. MODELLI BASE CON PYDANTIC (V2)
# =============================================================================

class PersonalInfo(BaseModel):
    """Informazioni personali studente (hashate per privacy)"""
    surname_hash: str = Field(..., description="Hash SHA-256 del cognome")
    name_hash: str = Field(..., description="Hash SHA-256 del nome")
    birth_date_hash: str = Field(..., description="Hash SHA-256 della data di nascita")
    student_id_hash: str = Field(..., description="Hash SHA-256 dell'ID studente")
    pseudonym: str = Field(..., description="Pseudonimo pubblico")

    # MODIFICA: Da @validator a @field_validator
    @field_validator('surname_hash', 'name_hash', 'birth_date_hash', 'student_id_hash')
    @classmethod
    def validate_hash_format(cls, v: str) -> str:
        if len(v) != 64 or not all(c in '0123456789abcdef' for c in v.lower()):
            raise ValueError('Deve essere un hash SHA-256 (64 caratteri hex)')
        return v.lower()

    # MODIFICA: Da @validator a @field_validator
    @field_validator('pseudonym')
    @classmethod
    def validate_pseudonym(cls, v: str) -> str:
        if not v or len(v) < 5 or len(v) > 50:
            raise ValueError('Pseudonimo deve essere 5-50 caratteri')
        return v


class ExamGrade(BaseModel):
    """Voto di un esame"""
    score: str = Field(..., description="Punteggio (es. 28/30, A, 3.7)")
    passed: bool = Field(..., description="Esame superato")
    grade_system: GradeSystem = Field(..., description="Sistema di voti")
    ects_grade: Optional[str] = Field(None, description="Equivalente ECTS (A-F)")

    # MODIFICA: Da @validator a @field_validator
    @field_validator('ects_grade')
    @classmethod
    def validate_ects_grade(cls, v: Optional[str]) -> Optional[str]:
        if v and v not in ['A', 'B', 'C', 'D', 'E', 'F']:
            raise ValueError('ECTS grade deve essere A, B, C, D, E, o F')
        return v


class Course(BaseModel):
    """Corso/Esame sostenuto"""
    course_name: str = Field(..., description="Nome del corso")
    course_code: str = Field(..., description="Codice del corso")
    isced_code: str = Field(..., description="Codice ISCED")
    grade: ExamGrade = Field(..., description="Voto ottenuto")
    exam_date: datetime.datetime = Field(..., description="Data esame")
    ects_credits: int = Field(..., ge=1, le=30, description="Crediti ECTS")
    professor: str = Field(..., description="Docente")
    course_description: Optional[str] = Field(None, description="Descrizione corso")
    prerequisites: List[str] = Field(default=[], description="Prerequisiti")
    learning_outcomes: List[str] = Field(default=[], description="Risultati apprendimento")

    # MODIFICA: Da @validator a @field_validator
    @field_validator('course_name')
    @classmethod
    def validate_course_name(cls, v: str) -> str:
        if not v or len(v) < 3 or len(v) > 200:
            raise ValueError('Nome corso deve essere 3-200 caratteri')
        return v

    # MODIFICA: Da @validator a @field_validator
    @field_validator('isced_code')
    @classmethod
    def validate_isced_code(cls, v: str) -> str:
        if not v or len(v) != 4 or not v.isdigit():
            raise ValueError('Codice ISCED deve essere 4 cifre')
        return v


class StudyPeriod(BaseModel):
    """Periodo di studio"""
    start_date: datetime.datetime = Field(..., description="Data inizio")
    end_date: datetime.datetime = Field(..., description="Data fine")
    study_type: StudyType = Field(..., description="Tipo di studio")
    academic_year: str = Field(..., description="Anno accademico (es. 2024/2025)")
    semester: Optional[str] = Field(None, description="Semestre")

    # MODIFICA: Da @validator a @field_validator
    @field_validator('academic_year')
    @classmethod
    def validate_academic_year(cls, v: str) -> str:
        if not v or '/' not in v:
            raise ValueError('Anno accademico deve essere formato YYYY/YYYY')
        years = v.split('/')
        if len(years) != 2:
            raise ValueError('Anno accademico deve essere formato YYYY/YYYY')
        try:
            year1, year2 = int(years[0]), int(years[1])
            if year2 != year1 + 1:
                raise ValueError('Secondo anno deve essere successivo al primo')
        except ValueError:
            raise ValueError('Anni devono essere numerici')
        return v

    # MODIFICA: Da @root_validator a @model_validator(mode='after') per validazione cross-field
    @model_validator(mode='after')
    def validate_dates(self) -> 'StudyPeriod':
        if self.start_date and self.end_date and self.start_date >= self.end_date:
            raise ValueError('Data fine deve essere successiva a data inizio')
        return self


class University(BaseModel):
    """Informazioni università"""
    name: str = Field(..., description="Nome università")
    country: str = Field(..., description="Paese (codice ISO 2 lettere)")
    erasmus_code: Optional[str] = Field(None, description="Codice Erasmus")
    website: Optional[str] = Field(None, description="Sito web")
    address: Optional[str] = Field(None, description="Indirizzo")
    city: str = Field(..., description="Città")

    # MODIFICA: Da @validator a @field_validator
    @field_validator('country')
    @classmethod
    def validate_country_code(cls, v: str) -> str:
        if not v or len(v) != 2 or not v.isalpha():
            raise ValueError('Codice paese deve essere 2 lettere ISO')
        return v.upper()

    # MODIFICA: Da @validator a @field_validator
    @field_validator('erasmus_code')
    @classmethod
    def validate_erasmus_code(cls, v: Optional[str]) -> Optional[str]:
        if v and (len(v) < 5 or len(v) > 15):
            raise ValueError('Codice Erasmus deve essere 5-15 caratteri')
        return v


class StudyProgram(BaseModel):
    """Programma di studio"""
    name: str = Field(..., description="Nome programma")
    isced_code: str = Field(..., description="Codice ISCED programma")
    eqf_level: EQFLevel = Field(..., description="Livello EQF")
    program_type: str = Field(..., description="Tipo programma (es. Laurea Magistrale)")
    field_of_study: str = Field(..., description="Campo di studio")

    # MODIFICA: Da @validator a @field_validator
    @field_validator('name')
    @classmethod
    def validate_program_name(cls, v: str) -> str:
        if not v or len(v) < 5 or len(v) > 200:
            raise ValueError('Nome programma deve essere 5-200 caratteri')
        return v


class DigitalSignature(BaseModel):
    """Firma digitale"""
    algorithm: str = Field(..., description="Algoritmo firma (es. RSA-SHA256-PSS)")
    value: str = Field(..., description="Valore firma (Base64)")
    timestamp: datetime.datetime = Field(..., description="Timestamp firma")
    signer_certificate_thumbprint: Optional[str] = Field(None, description="Thumbprint certificato firmatario")

    # MODIFICA: Da @validator a @field_validator
    @field_validator('algorithm')
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        allowed_algorithms = [
            'RSA-SHA256-PSS', 'RSA-SHA256-PKCS1v15',
            'RSA-SHA384-PSS', 'RSA-SHA512-PSS'
        ]
        if v not in allowed_algorithms:
            raise ValueError(f'Algoritmo deve essere uno di: {allowed_algorithms}')
        return v


class Metadata(BaseModel):
    """Metadati credenziale"""
    version: str = Field(default="1.2", description="Versione formato credenziale")
    credential_id: UUID4 = Field(default_factory=uuid.uuid4, description="ID univoco credenziale")
    issued_at: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc), description="Data emissione")
    expires_at: Optional[datetime.datetime] = Field(None, description="Data scadenza")
    merkle_root: str = Field(..., description="Radice Merkle Tree")
    revocation_registry_url: Optional[str] = Field(None, description="URL registro revoche")
    revocation_id: Optional[str] = Field(None, description="ID per verifica revoca")

    # MODIFICA: Da @validator a @field_validator
    @field_validator('version')
    @classmethod
    def validate_version(cls, v: str) -> str:
        if not v or v not in ['1.0', '1.1', '1.2']:
            raise ValueError('Versione deve essere 1.0, 1.1 o 1.2')
        return v

    # MODIFICA: Da @root_validator a @model_validator(mode='after')
    @model_validator(mode='after')
    def validate_expiry(self) -> 'Metadata':
        if self.issued_at and self.expires_at and self.expires_at <= self.issued_at:
            raise ValueError('Data scadenza deve essere successiva a data emissione')
        return self


# =============================================================================
# 3. MODELLO PRINCIPALE CREDENZIALE ACCADEMICA
# =============================================================================

class AcademicCredential(BaseModel):
    """Credenziale accademica completa"""
    metadata: Metadata = Field(..., description="Metadati credenziale")
    issuer: University = Field(..., description="Università emittente")
    subject: PersonalInfo = Field(..., description="Informazioni studente")
    study_period: StudyPeriod = Field(..., description="Periodo di studio")
    host_university: University = Field(..., description="Università ospitante")
    study_program: StudyProgram = Field(..., description="Programma di studio")
    courses: List[Course] = Field(..., min_length=1, description="Corsi sostenuti")
    total_ects_credits: int = Field(..., ge=0, description="Totale crediti ECTS")
    average_grade: Optional[str] = Field(None, description="Media voti")
    signature: Optional[DigitalSignature] = Field(None, description="Firma digitale")
    status: CredentialStatus = Field(default=CredentialStatus.DRAFT, description="Stato credenziale")

    # MODIFICA: Rimpiazzato validatori complessi con un unico @model_validator
    @model_validator(mode='after')
    def validate_academic_consistency(self) -> 'AcademicCredential':
        # 1. Valida coerenza crediti totali
        if self.courses:
            calculated_total = sum(course.ects_credits for course in self.courses)
            if self.total_ects_credits != calculated_total:
                raise ValueError(f'Crediti totali ({self.total_ects_credits}) non corrispondono alla somma ({calculated_total})')

        # 2. Valida che i corsi siano nel periodo di studio
        if self.study_period and self.courses:
            for course in self.courses:
                # Confronta date timezone-aware
                exam_date_utc = course.exam_date.astimezone(datetime.timezone.utc)
                start_date_utc = self.study_period.start_date.astimezone(datetime.timezone.utc)
                end_date_utc = self.study_period.end_date.astimezone(datetime.timezone.utc)
                if not (start_date_utc <= exam_date_utc <= end_date_utc):
                    raise ValueError(f"L'esame '{course.course_name}' del {course.exam_date.date()} è fuori dal periodo di studio.")
        
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario per serializzazione JSON"""
        # model_dump è il sostituto di dict() in Pydantic V2
        return self.model_dump(mode='json', exclude_none=False)

    def to_json(self, **kwargs) -> str:
        """Converte in JSON"""
        # model_dump_json è il sostituto di json() in Pydantic V2
        return self.model_dump_json(exclude_none=False, indent=2, **kwargs)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AcademicCredential':
        """Crea istanza da dizionario"""
        # parse_obj è deprecato, si usa model_validate
        return cls.model_validate(data)

    @classmethod
    def from_json(cls, json_str: str) -> 'AcademicCredential':
        """Crea istanza da JSON"""
        # parse_raw è deprecato, si usa model_validate_json
        return cls.model_validate_json(json_str)

    def calculate_merkle_root(self) -> str:
        """Calcola la radice del Merkle Tree dai corsi"""
        if not self.courses:
            return ""
        course_data = [course.model_dump(mode='json') for course in self.courses]
        merkle_tree = MerkleTree(course_data)
        return merkle_tree.get_merkle_root()
    
    def update_merkle_root(self):
        """Aggiorna la radice Merkle nei metadati"""
        self.metadata.merkle_root = self.calculate_merkle_root()

    def add_course(self, course: Course):
        """Aggiunge un corso e aggiorna i metadati"""
        self.courses.append(course)
        self.total_ects_credits = sum(c.ects_credits for c in self.courses)
        self.update_merkle_root()

    def remove_course(self, course_code: str) -> bool:
        """Rimuove un corso per codice"""
        original_length = len(self.courses)
        self.courses = [c for c in self.courses if c.course_code != course_code]
        if len(self.courses) < original_length:
            self.total_ects_credits = sum(c.ects_credits for c in self.courses)
            self.update_merkle_root()
            return True
        return False

    def get_course_by_code(self, course_code: str) -> Optional[Course]:
        """Ottiene corso per codice"""
        return next((c for c in self.courses if c.course_code == course_code), None)

    def calculate_average_grade(self, target_system: GradeSystem = GradeSystem.ITALIAN_30) -> Optional[str]:
        """Calcola media voti nel sistema specificato"""
        if not self.courses:
            return None
        total_weighted, total_credits = 0.0, 0
        for course in self.courses:
            if not course.grade.passed:
                continue
            numeric_grade = self._convert_grade_to_numeric(course.grade)
            if numeric_grade is not None:
                total_weighted += numeric_grade * course.ects_credits
                total_credits += course.ects_credits
        if total_credits == 0:
            return None
        average = total_weighted / total_credits
        return f"{average:.2f}/30"

    def _convert_grade_to_numeric(self, grade: ExamGrade) -> Optional[float]:
        """Converte un voto in formato numerico (sistema italiano 30/30)"""
        try:
            if grade.grade_system == GradeSystem.ITALIAN_30:
                return float(grade.score.split('/')[0]) if '/' in grade.score else float(grade.score)
            elif grade.grade_system == GradeSystem.ECTS_GRADE:
                ects_map = {'A': 30, 'B': 27, 'C': 24, 'D': 21, 'E': 18, 'F': 0}
                return float(ects_map.get(grade.score.upper(), 18))
            elif grade.grade_system == GradeSystem.FRENCH_20:
                french_grade = float(grade.score.split('/')[0]) if '/' in grade.score else float(grade.score)
                return (french_grade / 20) * 30
            return None
        except (ValueError, AttributeError):
            return None

    def is_valid(self) -> Tuple[bool, List[str]]:
        """Verifica validità della credenziale"""
        errors = []
        if self.metadata.merkle_root != self.calculate_merkle_root():
            errors.append("Integrità compromessa: Merkle root non corrispondente.")
        if self.metadata.expires_at and datetime.datetime.now(datetime.timezone.utc) > self.metadata.expires_at:
            self.status = CredentialStatus.EXPIRED
            errors.append("Credenziale scaduta.")
        if self.status in [CredentialStatus.REVOKED, CredentialStatus.SUSPENDED, CredentialStatus.EXPIRED]:
            errors.append(f"Credenziale non attiva (stato: {self.status.value}).")
        if self.status == CredentialStatus.ACTIVE and not self.signature:
            errors.append("Credenziale attiva ma priva di firma digitale.")
        return len(errors) == 0, errors

    def get_summary(self) -> Dict[str, Any]:
        """Ottiene riassunto della credenziale"""
        return {
            'credential_id': str(self.metadata.credential_id), 'version': self.metadata.version,
            'status': self.status.value, 'issuer': self.issuer.name, 'host_university': self.host_university.name,
            'subject_pseudonym': self.subject.pseudonym,
            'study_period': f"{self.study_period.start_date.date()} - {self.study_period.end_date.date()}",
            'study_type': self.study_period.study_type.value, 'academic_year': self.study_period.academic_year,
            'program': self.study_program.name, 'total_courses': len(self.courses),
            'total_ects': self.total_ects_credits, 'average_grade': self.average_grade,
            'issued_at': self.metadata.issued_at.isoformat(),
            'expires_at': self.metadata.expires_at.isoformat() if self.metadata.expires_at else None,
            'signed': self.signature is not None
        }

# =============================================================================
# 4. FACTORY E BUILDERS
# =============================================================================

class CredentialFactory:
    """Factory per creare credenziali accademiche"""
    @staticmethod
    def create_erasmus_credential(
        issuer_university: University,
        host_university: University,
        student_info: PersonalInfo,
        courses: List[Course],
        study_period: StudyPeriod,
        study_program: StudyProgram
    ) -> AcademicCredential:
        """Crea una credenziale Erasmus standard"""
        
        # Calcola totale crediti
        total_credits = sum(course.ects_credits for course in courses)
        
        # Crea metadati
        metadata = Metadata(
            merkle_root="placeholder", # Verrà calcolato dopo la creazione
            issued_at=datetime.datetime.now(datetime.timezone.utc)
        )
        
        # Crea credenziale
        credential = AcademicCredential(
            metadata=metadata,
            issuer=issuer_university,
            subject=student_info,
            study_period=study_period,
            host_university=host_university,
            study_program=study_program,
            courses=courses,
            total_ects_credits=total_credits,
            status=CredentialStatus.DRAFT
        )
        
        # Aggiorna Merkle root e media
        credential.update_merkle_root()
        credential.average_grade = credential.calculate_average_grade()
        
        return credential
    
    @staticmethod
    def create_sample_credential() -> AcademicCredential:
        """Crea una credenziale di esempio per testing - SCENARIO ERASMUS CORRETTO"""
        
        # CORREZIONE: Inverti issuer e host_university per scenario realistico
        # Università francese (EMETTE la credenziale - ha certificato e chiave)
        univ_rennes = University(
            name="Université de Rennes", 
            country="FR", 
            erasmus_code="F RENNES01", 
            city="Rennes", 
            website="https://www.univ-rennes1.fr"
        )
        
        # Università italiana (OSPITA lo studente normalmente - verifica la credenziale)
        univ_salerno = University(
            name="Università degli Studi di Salerno", 
            country="IT", 
            erasmus_code="I SALERNO01", 
            city="Fisciano", 
            website="https://www.unisa.it"
        )
        
        crypto_utils = CryptoUtils()
        
        # Studente italiano
        student_info = PersonalInfo(
            surname_hash=crypto_utils.sha256_hash_string("Rossi"), 
            name_hash=crypto_utils.sha256_hash_string("Mario"),
            birth_date_hash=crypto_utils.sha256_hash_string("1995-03-15"), 
            student_id_hash=crypto_utils.sha256_hash_string("0622702628"),
            pseudonym="student_mario_r"
        )
        
        # Periodo Erasmus in Francia
        study_period = StudyPeriod(
            start_date=datetime.datetime(2024, 9, 1, tzinfo=datetime.timezone.utc),
            end_date=datetime.datetime(2025, 2, 28, tzinfo=datetime.timezone.utc),
            study_type=StudyType.ERASMUS, 
            academic_year="2024/2025", 
            semester="Fall 2024"
        )
        
        # Programma di studio in Francia
        study_program = StudyProgram(
            name="Computer Science and Engineering", 
            isced_code="0613", 
            eqf_level=EQFLevel.LEVEL_7,
            program_type="Laurea Magistrale", 
            field_of_study="Informatica"
        )
        
        # Corsi sostenuti in Francia (con voti francesi convertiti)
        courses = [
            Course(
                course_name="Algoritmes et Protocoles pour la Sécurité", 
                course_code="INF/01-APS", 
                isced_code="0613", 
                grade=ExamGrade(
                    score="B", 
                    passed=True, 
                    grade_system=GradeSystem.ECTS_GRADE, 
                    ects_grade="B"
                ), 
                exam_date=datetime.datetime(2024, 12, 15, 9, 30, tzinfo=datetime.timezone.utc), 
                ects_credits=6, 
                professor="Prof. Jean Dupont", 
                course_description="Algorithmes cryptographiques et protocoles de sécurité"
            ),
            Course(
                course_name="Intelligence Artificielle", 
                course_code="INF/01-AI", 
                isced_code="0613", 
                grade=ExamGrade(
                    score="A", 
                    passed=True, 
                    grade_system=GradeSystem.ECTS_GRADE, 
                    ects_grade="A"
                ), 
                exam_date=datetime.datetime(2024, 11, 20, 14, 0, tzinfo=datetime.timezone.utc), 
                ects_credits=8, 
                professor="Prof. Marie Martin", 
                course_description="Fondements de l'intelligence artificielle et machine learning"
            ),
            Course(
                course_name="Systèmes Distribués", 
                course_code="INF/01-SD", 
                isced_code="0613", 
                grade=ExamGrade(
                    score="C", 
                    passed=True, 
                    grade_system=GradeSystem.ECTS_GRADE, 
                    ects_grade="C"
                ), 
                exam_date=datetime.datetime(2025, 1, 10, 10, 0, tzinfo=datetime.timezone.utc), 
                ects_credits=6, 
                professor="Prof. Pierre Durand", 
                course_description="Architectures et algorithmes pour systèmes distribués"
            )
        ]
        
        total_credits = sum(c.ects_credits for c in courses)
        metadata = Metadata(merkle_root="placeholder")
        
        # CORREZIONE CRUCIALE: issuer = Rennes (ha certificato), host = Salerno (studente italiano)
        credential = AcademicCredential(
            metadata=metadata, 
            issuer=univ_rennes,           # 🇫🇷 EMETTE la credenziale (ha certificato)
            subject=student_info, 
            study_period=study_period,
            host_university=univ_salerno, # 🇮🇹 OSPITA lo studente (università di origine)
            study_program=study_program, 
            courses=courses,
            total_ects_credits=total_credits
        )
        
        credential.update_merkle_root()
        credential.average_grade = credential.calculate_average_grade()
        return credential


# =============================================================================
# 5. DEMO E TESTING
# =============================================================================

def demo_credential_models():
    # ... (il corpo della funzione demo rimane sostanzialmente invariato)
    print("📋" * 40)
    print("DEMO CREDENTIAL MODELS (PYDANTIC V2)")
    print("Struttura Credenziali Accademiche")
    print("📋" * 40)
    
    try:
        # 1. Crea credenziale di esempio
        print("\n1️⃣ CREAZIONE CREDENZIALE DI ESEMPIO")
        credential = CredentialFactory.create_sample_credential()
        print(f"✅ Credenziale creata con successo!")
        
        # 2. Serializzazione JSON
        print("\n2️⃣ SERIALIZZAZIONE JSON")
        json_data = credential.to_json()
        output_file = Path("./credentials/sample_credential.json")
        output_file.parent.mkdir(exist_ok=True)
        output_file.write_text(json_data, encoding='utf-8')
        print(f"💾 Credenziale salvata: {output_file}")
        
        # 3. Deserializzazione e Verifica
        print("\n3️⃣ DESERIALIZZAZIONE E VERIFICA")
        loaded_credential = AcademicCredential.from_json(output_file.read_text(encoding='utf-8'))
        assert loaded_credential.metadata.credential_id == credential.metadata.credential_id
        print("✅ Deserializzazione corretta e ID corrispondente.")
        
        # 4. Validazione finale
        print("\n4️⃣ VALIDAZIONE FINALE")
        is_valid, errors = loaded_credential.is_valid()
        if is_valid:
            print("✅ Credenziale finale VALIDA")
        else:
            print(f"❌ Errori trovati: {errors}")

        print("\n" + "✅" * 40)
        return credential
        
    except Exception as e:
        print(f"\n❌ ERRORE DURANTE DEMO: {e}")
        import traceback
        traceback.print_exc()
        return None

# =============================================================================
# 6. MAIN - PUNTO DI INGRESSO
# =============================================================================

if __name__ == "__main__":
    demo_credential_models()