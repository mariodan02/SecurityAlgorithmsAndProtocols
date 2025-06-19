# =============================================================================
# FASE 3: STRUTTURA CREDENZIALI ACCADEMICHE - MODELS
# File: credentials/models.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import json
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import uuid

# Pydantic per validazione dati
from pydantic import BaseModel, Field, validator, root_validator
from pydantic.types import UUID4

# Import moduli interni
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from crypto.foundations import CryptoUtils, MerkleTree
except ImportError:
    print("⚠️  Assicurati che crypto/foundations.py sia presente nel progetto")
    raise


# =============================================================================
# 1. ENUMS E COSTANTI
# =============================================================================

class CredentialStatus(Enum):
    """Stati possibili di una credenziale"""
    DRAFT = "draft"                 # Bozza
    ACTIVE = "active"               # Attiva
    REVOKED = "revoked"            # Revocata
    EXPIRED = "expired"            # Scaduta
    SUSPENDED = "suspended"        # Sospesa


class StudyType(Enum):
    """Tipologie di studio"""
    ERASMUS = "erasmus"
    EXCHANGE = "exchange"
    DOUBLE_DEGREE = "double_degree"
    REGULAR = "regular"


class GradeSystem(Enum):
    """Sistemi di voti"""
    ITALIAN_30 = "italian_30"        # 18-30/30
    FRENCH_20 = "french_20"          # 0-20/20
    GERMAN_6 = "german_6"            # 1.0-6.0
    ECTS_GRADE = "ects_grade"        # A, B, C, D, E, F
    US_GPA = "us_gpa"                # 0.0-4.0


class EQFLevel(Enum):
    """European Qualifications Framework Levels"""
    LEVEL_6 = "6"  # Bachelor
    LEVEL_7 = "7"  # Master
    LEVEL_8 = "8"  # PhD


# =============================================================================
# 2. MODELLI BASE CON PYDANTIC
# =============================================================================

class PersonalInfo(BaseModel):
    """Informazioni personali studente (hashate per privacy)"""
    
    surname_hash: str = Field(..., description="Hash SHA-256 del cognome")
    name_hash: str = Field(..., description="Hash SHA-256 del nome")
    birth_date_hash: str = Field(..., description="Hash SHA-256 della data di nascita")
    student_id_hash: str = Field(..., description="Hash SHA-256 dell'ID studente")
    pseudonym: str = Field(..., description="Pseudonimo pubblico")
    
    @validator('surname_hash', 'name_hash', 'birth_date_hash', 'student_id_hash')
    def validate_hash_format(cls, v):
        """Valida che sia un hash SHA-256 valido"""
        if len(v) != 64 or not all(c in '0123456789abcdef' for c in v.lower()):
            raise ValueError('Deve essere un hash SHA-256 (64 caratteri hex)')
        return v.lower()
    
    @validator('pseudonym')
    def validate_pseudonym(cls, v):
        """Valida formato pseudonimo"""
        if not v or len(v) < 5 or len(v) > 50:
            raise ValueError('Pseudonimo deve essere 5-50 caratteri')
        return v


class ExamGrade(BaseModel):
    """Voto di un esame"""
    
    score: str = Field(..., description="Punteggio (es. 28/30, A, 3.7)")
    passed: bool = Field(..., description="Esame superato")
    grade_system: GradeSystem = Field(..., description="Sistema di voti")
    ects_grade: Optional[str] = Field(None, description="Equivalente ECTS (A-F)")
    
    @validator('ects_grade')
    def validate_ects_grade(cls, v):
        """Valida grade ECTS"""
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
    prerequisites: Optional[List[str]] = Field(default=[], description="Prerequisiti")
    learning_outcomes: Optional[List[str]] = Field(default=[], description="Risultati apprendimento")
    
    @validator('course_name')
    def validate_course_name(cls, v):
        """Valida nome corso"""
        if not v or len(v) < 3 or len(v) > 200:
            raise ValueError('Nome corso deve essere 3-200 caratteri')
        return v
    
    @validator('isced_code')
    def validate_isced_code(cls, v):
        """Valida codice ISCED"""
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
    
    @validator('academic_year')
    def validate_academic_year(cls, v):
        """Valida formato anno accademico"""
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
    
    @root_validator
    def validate_dates(cls, values):
        """Valida coerenza date"""
        start = values.get('start_date')
        end = values.get('end_date')
        
        if start and end and start >= end:
            raise ValueError('Data fine deve essere successiva a data inizio')
        
        return values


class University(BaseModel):
    """Informazioni università"""
    
    name: str = Field(..., description="Nome università")
    country: str = Field(..., description="Paese (codice ISO 2 lettere)")
    erasmus_code: Optional[str] = Field(None, description="Codice Erasmus")
    website: Optional[str] = Field(None, description="Sito web")
    address: Optional[str] = Field(None, description="Indirizzo")
    city: str = Field(..., description="Città")
    
    @validator('country')
    def validate_country_code(cls, v):
        """Valida codice paese ISO"""
        if not v or len(v) != 2 or not v.isalpha():
            raise ValueError('Codice paese deve essere 2 lettere ISO')
        return v.upper()
    
    @validator('erasmus_code')
    def validate_erasmus_code(cls, v):
        """Valida codice Erasmus"""
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
    
    @validator('name')
    def validate_program_name(cls, v):
        """Valida nome programma"""
        if not v or len(v) < 5 or len(v) > 200:
            raise ValueError('Nome programma deve essere 5-200 caratteri')
        return v


class DigitalSignature(BaseModel):
    """Firma digitale"""
    
    algorithm: str = Field(..., description="Algoritmo firma (es. RSA-SHA256-PSS)")
    value: str = Field(..., description="Valore firma (Base64)")
    timestamp: datetime.datetime = Field(..., description="Timestamp firma")
    signer_certificate_thumbprint: Optional[str] = Field(None, description="Thumbprint certificato firmatario")
    
    @validator('algorithm')
    def validate_algorithm(cls, v):
        """Valida algoritmo firma"""
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
    issued_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow, description="Data emissione")
    expires_at: Optional[datetime.datetime] = Field(None, description="Data scadenza")
    merkle_root: str = Field(..., description="Radice Merkle Tree")
    revocation_registry_url: Optional[str] = Field(None, description="URL registro revoche")
    revocation_id: Optional[str] = Field(None, description="ID per verifica revoca")
    
    @validator('version')
    def validate_version(cls, v):
        """Valida versione formato"""
        if not v or v not in ['1.0', '1.1', '1.2']:
            raise ValueError('Versione deve essere 1.0, 1.1 o 1.2')
        return v
    
    @root_validator
    def validate_expiry(cls, values):
        """Valida data scadenza"""
        issued = values.get('issued_at')
        expires = values.get('expires_at')
        
        if issued and expires and expires <= issued:
            raise ValueError('Data scadenza deve essere successiva a data emissione')
        
        return values


# =============================================================================
# 3. MODELLO PRINCIPALE CREDENZIALE ACCADEMICA
# =============================================================================

class AcademicCredential(BaseModel):
    """Credenziale accademica completa"""
    
    # Metadati
    metadata: Metadata = Field(..., description="Metadati credenziale")
    
    # Ente emittente
    issuer: University = Field(..., description="Università emittente")
    
    # Soggetto (studente)
    subject: PersonalInfo = Field(..., description="Informazioni studente")
    
    # Contenuto accademico
    study_period: StudyPeriod = Field(..., description="Periodo di studio")
    host_university: University = Field(..., description="Università ospitante")
    study_program: StudyProgram = Field(..., description="Programma di studio")
    courses: List[Course] = Field(..., description="Corsi sostenuti")
    
    # Riassunto
    total_ects_credits: int = Field(..., ge=0, description="Totale crediti ECTS")
    average_grade: Optional[str] = Field(None, description="Media voti")
    
    # Firma digitale
    signature: Optional[DigitalSignature] = Field(None, description="Firma digitale")
    
    # Status
    status: CredentialStatus = Field(default=CredentialStatus.DRAFT, description="Stato credenziale")
    
    @validator('courses')
    def validate_courses_not_empty(cls, v):
        """Valida che ci siano corsi"""
        if not v:
            raise ValueError('Deve esserci almeno un corso')
        return v
    
    @validator('total_ects_credits')
    def validate_total_credits(cls, v, values):
        """Valida coerenza crediti totali"""
        courses = values.get('courses', [])
        if courses:
            calculated_total = sum(course.ects_credits for course in courses)
            if v != calculated_total:
                raise ValueError(f'Crediti totali ({v}) non corrispondono alla somma ({calculated_total})')
        return v
    
    @root_validator
    def validate_study_period_courses(cls, values):
        """Valida che i corsi siano nel periodo di studio"""
        study_period = values.get('study_period')
        courses = values.get('courses', [])
        
        if study_period and courses:
            for course in courses:
                if not (study_period.start_date <= course.exam_date <= study_period.end_date):
                    raise ValueError(f'Esame {course.course_name} fuori dal periodo di studio')
        
        return values
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario per serializzazione JSON"""
        return json.loads(self.json(exclude_none=False, ensure_ascii=False))
    
    def to_json(self, **kwargs) -> str:
        """Converte in JSON"""
        return self.json(exclude_none=False, ensure_ascii=False, indent=2, **kwargs)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AcademicCredential':
        """Crea istanza da dizionario"""
        return cls.parse_obj(data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'AcademicCredential':
        """Crea istanza da JSON"""
        return cls.parse_raw(json_str)
    
    def calculate_merkle_root(self) -> str:
        """Calcola la radice del Merkle Tree dai corsi"""
        if not self.courses:
            return ""
        
        # Crea lista dati per Merkle Tree
        course_data = [course.dict() for course in self.courses]
        
        # Costruisce Merkle Tree
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
        for course in self.courses:
            if course.course_code == course_code:
                return course
        return None
    
    def calculate_average_grade(self, target_system: GradeSystem = GradeSystem.ITALIAN_30) -> Optional[str]:
        """Calcola media voti nel sistema specificato"""
        if not self.courses:
            return None
        
        # Implementazione semplificata - converte tutto al sistema italiano 30/30
        total_weighted = 0.0
        total_credits = 0
        
        for course in self.courses:
            if not course.grade.passed:
                continue
            
            # Conversione semplificata dei voti
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
                # Estrae voto numerico (es. "28/30" -> 28.0)
                if '/' in grade.score:
                    return float(grade.score.split('/')[0])
                return float(grade.score)
            
            elif grade.grade_system == GradeSystem.ECTS_GRADE:
                # Conversione ECTS -> 30/30
                ects_map = {'A': 30, 'B': 27, 'C': 24, 'D': 21, 'E': 18, 'F': 0}
                return float(ects_map.get(grade.score, 18))
            
            elif grade.grade_system == GradeSystem.FRENCH_20:
                # Conversione 20/20 -> 30/30
                if '/' in grade.score:
                    french_grade = float(grade.score.split('/')[0])
                else:
                    french_grade = float(grade.score)
                return (french_grade / 20) * 30
            
            # Altri sistemi...
            return None
            
        except (ValueError, AttributeError):
            return None
    
    def is_valid(self) -> Tuple[bool, List[str]]:
        """Verifica validità della credenziale"""
        errors = []
        
        # Verifica Merkle root
        calculated_root = self.calculate_merkle_root()
        if self.metadata.merkle_root != calculated_root:
            errors.append("Merkle root non corrispondente")
        
        # Verifica scadenza
        if self.metadata.expires_at and datetime.datetime.utcnow() > self.metadata.expires_at:
            errors.append("Credenziale scaduta")
        
        # Verifica status
        if self.status in [CredentialStatus.REVOKED, CredentialStatus.SUSPENDED]:
            errors.append(f"Credenziale {self.status.value}")
        
        # Verifica firma presente (per credenziali attive)
        if self.status == CredentialStatus.ACTIVE and not self.signature:
            errors.append("Firma digitale mancante")
        
        return len(errors) == 0, errors
    
    def get_summary(self) -> Dict[str, Any]:
        """Ottiene riassunto della credenziale"""
        return {
            'credential_id': str(self.metadata.credential_id),
            'version': self.metadata.version,
            'status': self.status.value,
            'issuer': self.issuer.name,
            'host_university': self.host_university.name,
            'subject_pseudonym': self.subject.pseudonym,
            'study_period': f"{self.study_period.start_date.date()} - {self.study_period.end_date.date()}",
            'study_type': self.study_period.study_type.value,
            'academic_year': self.study_period.academic_year,
            'program': self.study_program.name,
            'total_courses': len(self.courses),
            'total_ects': self.total_ects_credits,
            'average_grade': self.average_grade,
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
            version="1.2",
            credential_id=uuid.uuid4(),
            issued_at=datetime.datetime.utcnow(),
            merkle_root=""  # Verrà calcolato automaticamente
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
        """Crea una credenziale di esempio per testing"""
        
        # Università
        univ_salerno = University(
            name="Università degli Studi di Salerno",
            country="IT",
            erasmus_code="I SALERNO01",
            city="Fisciano",
            website="https://www.unisa.it"
        )
        
        univ_rennes = University(
            name="Université de Rennes",
            country="FR",
            erasmus_code="F RENNES01",
            city="Rennes",
            website="https://www.univ-rennes1.fr"
        )
        
        # Studente (dati hashati)
        crypto_utils = CryptoUtils()
        student_info = PersonalInfo(
            surname_hash=crypto_utils.sha256_hash_string("Rossi"),
            name_hash=crypto_utils.sha256_hash_string("Mario"),
            birth_date_hash=crypto_utils.sha256_hash_string("1995-03-15"),
            student_id_hash=crypto_utils.sha256_hash_string("0622702628"),
            pseudonym="student_mario_r"
        )
        
        # Periodo di studio
        study_period = StudyPeriod(
            start_date=datetime.datetime(2024, 9, 1),
            end_date=datetime.datetime(2025, 2, 28),
            study_type=StudyType.ERASMUS,
            academic_year="2024/2025",
            semester="Fall 2024"
        )
        
        # Programma di studio
        study_program = StudyProgram(
            name="Computer Science and Engineering",
            isced_code="0613",
            eqf_level=EQFLevel.LEVEL_7,
            program_type="Laurea Magistrale",
            field_of_study="Informatica"
        )
        
        # Corsi
        courses = [
            Course(
                course_name="Algoritmi e Protocolli per la Sicurezza",
                course_code="INF/01-APS",
                isced_code="0613",
                grade=ExamGrade(
                    score="28/30",
                    passed=True,
                    grade_system=GradeSystem.ITALIAN_30,
                    ects_grade="B"
                ),
                exam_date=datetime.datetime(2024, 12, 15, 9, 30),
                ects_credits=6,
                professor="Prof. Carlo Mazzocca",
                course_description="Algoritmi crittografici e protocolli di sicurezza"
            ),
            Course(
                course_name="Intelligenza Artificiale",
                course_code="INF/01-AI",
                isced_code="0613",
                grade=ExamGrade(
                    score="30/30",
                    passed=True,
                    grade_system=GradeSystem.ITALIAN_30,
                    ects_grade="A"
                ),
                exam_date=datetime.datetime(2024, 11, 20, 14, 0),
                ects_credits=8,
                professor="Prof.ssa Anna Bianchi",
                course_description="Fondamenti di intelligenza artificiale e machine learning"
            ),
            Course(
                course_name="Sistemi Distribuiti",
                course_code="INF/01-SD",
                isced_code="0613",
                grade=ExamGrade(
                    score="25/30",
                    passed=True,
                    grade_system=GradeSystem.ITALIAN_30,
                    ects_grade="C"
                ),
                exam_date=datetime.datetime(2025, 1, 10, 10, 0),
                ects_credits=6,
                professor="Prof. Giuseppe Verdi",
                course_description="Architetture e algoritmi per sistemi distribuiti"
            )
        ]
        
        # Crea credenziale
        return CredentialFactory.create_erasmus_credential(
            issuer_university=univ_salerno,
            host_university=univ_rennes,
            student_info=student_info,
            courses=courses,
            study_period=study_period,
            study_program=study_program
        )


# =============================================================================
# 5. DEMO E TESTING
# =============================================================================

def demo_credential_models():
    """Demo dei modelli credenziali"""
    
    print("📋" * 40)
    print("DEMO CREDENTIAL MODELS")
    print("Struttura Credenziali Accademiche")
    print("📋" * 40)
    
    try:
        # 1. Crea credenziale di esempio
        print("\n1️⃣ CREAZIONE CREDENZIALE DI ESEMPIO")
        
        credential = CredentialFactory.create_sample_credential()
        print(f"✅ Credenziale creata:")
        print(f"   ID: {credential.metadata.credential_id}")
        print(f"   Versione: {credential.metadata.version}")
        print(f"   Status: {credential.status.value}")
        print(f"   Corsi: {len(credential.courses)}")
        print(f"   Crediti totali: {credential.total_ects_credits}")
        
        # 2. Validazione
        print("\n2️⃣ VALIDAZIONE CREDENZIALE")
        
        is_valid, errors = credential.is_valid()
        if is_valid:
            print("✅ Credenziale VALIDA")
        else:
            print("❌ Credenziale NON VALIDA:")
            for error in errors:
                print(f"   - {error}")
        
        # 3. Serializzazione JSON
        print("\n3️⃣ SERIALIZZAZIONE JSON")
        
        json_data = credential.to_json()
        print(f"✅ JSON generato ({len(json_data)} caratteri)")
        
        # Salva su file
        output_file = "./credentials/sample_credential.json"
        Path("./credentials").mkdir(exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(json_data)
        
        print(f"💾 Credenziale salvata: {output_file}")
        
        # 4. Deserializzazione
        print("\n4️⃣ DESERIALIZZAZIONE E VERIFICA")
        
        # Ricarica da JSON
        with open(output_file, 'r', encoding='utf-8') as f:
            loaded_json = f.read()
        
        loaded_credential = AcademicCredential.from_json(loaded_json)
        
        # Verifica equivalenza
        if loaded_credential.metadata.credential_id == credential.metadata.credential_id:
            print("✅ Deserializzazione corretta")
        else:
            print("❌ Errore deserializzazione")
        
        # 5. Operazioni sui corsi
        print("\n5️⃣ OPERAZIONI SUI CORSI")
        
        # Aggiungi corso
        new_course = Course(
            course_name="Blockchain e Cryptocurrency",
            course_code="INF/01-BC",
            isced_code="0613",
            grade=ExamGrade(
                score="29/30",
                passed=True,
                grade_system=GradeSystem.ITALIAN_30,
                ects_grade="A"
            ),
            exam_date=datetime.datetime(2025, 2, 15, 11, 0),
            ects_credits=4,
            professor="Prof. Francesco Cauteruccio"
        )
        
        original_courses = len(credential.courses)
        credential.add_course(new_course)
        
        print(f"✅ Corso aggiunto: {len(credential.courses)} corsi (+{len(credential.courses) - original_courses})")
        print(f"   Nuovi crediti totali: {credential.total_ects_credits}")
        
        # Cerca corso
        found_course = credential.get_course_by_code("INF/01-AI")
        if found_course:
            print(f"✅ Corso trovato: {found_course.course_name}")
        
        # 6. Calcolo media
        print("\n6️⃣ CALCOLO MEDIA VOTI")
        
        average = credential.calculate_average_grade()
        if average:
            credential.average_grade = average
            print(f"✅ Media calcolata: {average}")
        
        # 7. Merkle Tree
        print("\n7️⃣ MERKLE TREE E INTEGRITÀ")
        
        original_root = credential.metadata.merkle_root
        credential.update_merkle_root()
        new_root = credential.metadata.merkle_root
        
        print(f"   Root originale: {original_root[:16]}...")
        print(f"   Root aggiornata: {new_root[:16]}...")
        
        if original_root != new_root:
            print("✅ Merkle root aggiornata correttamente")
        
        # 8. Riassunto
        print("\n8️⃣ RIASSUNTO CREDENZIALE")
        
        summary = credential.get_summary()
        
        print("📊 Riassunto:")
        for key, value in summary.items():
            print(f"   {key}: {value}")
        
        # 9. Validazione finale
        print("\n9️⃣ VALIDAZIONE FINALE")
        
        is_valid, errors = credential.is_valid()
        if is_valid:
            print("✅ Credenziale finale VALIDA")
        else:
            print("❌ Errori trovati:")
            for error in errors:
                print(f"   - {error}")
        
        print("\n" + "✅" * 40)
        print("DEMO CREDENTIAL MODELS COMPLETATA!")
        print("✅" * 40)
        
        print(f"\n📁 File generato: {output_file}")
        print(f"📋 Credenziale ID: {credential.metadata.credential_id}")
        print(f"🎓 Studente: {credential.subject.pseudonym}")
        print(f"🏫 Università: {credential.issuer.name} → {credential.host_university.name}")
        print(f"📚 Corsi: {len(credential.courses)} ({credential.total_ects_credits} ECTS)")
        
        return credential
        
    except Exception as e:
        print(f"\n❌ Errore durante demo: {e}")
        import traceback
        traceback.print_exc()
        return None


# =============================================================================
# 6. MAIN - PUNTO DI INGRESSO
# =============================================================================

if __name__ == "__main__":
    print("📋" * 50)
    print("FASE 3: STRUTTURA CREDENZIALI ACCADEMICHE")
    print("Modelli Dati e Validazione")
    print("📋" * 50)
    
    # Esegui demo
    sample_credential = demo_credential_models()
    
    if sample_credential:
        print("\n🎉 FASE 3 - MODELS COMPLETATA!")
        print("\nFunzionalità implementate:")
        print("✅ Modelli Pydantic per validazione")
        print("✅ Credenziale accademica completa")
        print("✅ Integrazione Merkle Tree")
        print("✅ Serializzazione/Deserializzazione JSON")
        print("✅ Validazione dati e coerenza")
        print("✅ Factory per creazione credenziali")
        print("✅ Operazioni CRUD sui corsi")
        print("✅ Calcolo automatico medie e crediti")
        
        print(f"\n🚀 Pronti per Issuer e Validator!")
    else:
        print("\n❌ Errore nella demo models")