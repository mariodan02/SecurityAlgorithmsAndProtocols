"""
Modelli dati per le credenziali accademiche utilizzando Pydantic V2.

Questo modulo definisce le strutture dati principali per:
- Credenziali accademiche complete
- Informazioni studente e università
- Corsi ed esami
- Firma digitale e metadati
"""

import datetime
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic.types import UUID4

try:
    from crypto.foundations import CryptoUtils, MerkleTree
except ImportError:
    raise ImportError(
        "Moduli crypto non disponibili. "
        "Assicurati che CryptoUtils e MerkleTree siano installati."
    )


class CredentialStatus(Enum):
    """Stati possibili di una credenziale accademica."""
    DRAFT = "draft"
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    SUSPENDED = "suspended"


class StudyType(Enum):
    """Tipologie di programmi di studio supportati."""
    ERASMUS = "erasmus"
    EXCHANGE = "exchange"
    DOUBLE_DEGREE = "double_degree"
    REGULAR = "regular"


class GradeSystem(Enum):
    """Sistemi di valutazione supportati."""
    ITALIAN_30 = "italian_30"
    FRENCH_20 = "french_20"
    GERMAN_6 = "german_6"
    ECTS_GRADE = "ects_grade"
    US_GPA = "us_gpa"


class EQFLevel(Enum):
    """Livelli del Quadro Europeo delle Qualificazioni."""
    LEVEL_6 = "6"  # Laurea triennale
    LEVEL_7 = "7"  # Laurea magistrale
    LEVEL_8 = "8"  # Dottorato


class PersonalInfo(BaseModel):
    """
    Informazioni personali dello studente con hash per privacy.
    
    Tutti i dati sensibili sono hashati con SHA-256 per proteggere
    la privacy mantenendo la verificabilità.
    """
    surname_hash: str = Field(..., description="Hash SHA-256 del cognome")
    name_hash: str = Field(..., description="Hash SHA-256 del nome")
    birth_date_hash: str = Field(..., description="Hash SHA-256 della data di nascita")
    student_id_hash: str = Field(..., description="Hash SHA-256 dell'ID studente")
    pseudonym: str = Field(..., description="Pseudonimo pubblico")

    @field_validator('surname_hash', 'name_hash', 'birth_date_hash', 'student_id_hash')
    @classmethod
    def validate_hash_format(cls, v: str) -> str:
        """Valida che il valore sia un hash SHA-256 valido."""
        if len(v) != 64 or not all(c in '0123456789abcdef' for c in v.lower()):
            raise ValueError('Deve essere un hash SHA-256 (64 caratteri hex)')
        return v.lower()

    @field_validator('pseudonym')
    @classmethod
    def validate_pseudonym(cls, v: str) -> str:
        """Valida il formato dello pseudonimo."""
        if not v or len(v) < 5 or len(v) > 50:
            raise ValueError('Pseudonimo deve essere 5-50 caratteri')
        return v


class ExamGrade(BaseModel):
    """Rappresenta il voto di un esame sostenuto."""
    score: str = Field(..., description="Punteggio (es. 28/30, A, 3.7)")
    passed: bool = Field(..., description="Indica se l'esame è stato superato")
    grade_system: GradeSystem = Field(..., description="Sistema di valutazione utilizzato")
    ects_grade: Optional[str] = Field(None, description="Equivalente ECTS (A-F)")

    @field_validator('ects_grade')
    @classmethod
    def validate_ects_grade(cls, v: Optional[str]) -> Optional[str]:
        """Valida il voto ECTS se presente."""
        if v and v not in ['A', 'B', 'C', 'D', 'E', 'F']:
            raise ValueError('ECTS grade deve essere A, B, C, D, E, o F')
        return v


class Course(BaseModel):
    """Rappresenta un corso/esame sostenuto durante il periodo di studio."""
    course_name: str = Field(..., description="Nome del corso")
    course_code: str = Field(..., description="Codice identificativo del corso")
    isced_code: str = Field(..., description="Codice ISCED del settore disciplinare")
    grade: ExamGrade = Field(..., description="Voto ottenuto")
    exam_date: datetime.datetime = Field(..., description="Data dell'esame")
    ects_credits: int = Field(..., ge=1, le=30, description="Crediti ECTS assegnati")
    professor: str = Field(..., description="Nome del docente")
    course_description: Optional[str] = Field(None, description="Descrizione del corso")
    prerequisites: List[str] = Field(default=[], description="Prerequisiti richiesti")
    learning_outcomes: List[str] = Field(default=[], description="Risultati di apprendimento")

    @field_validator('course_name')
    @classmethod
    def validate_course_name(cls, v: str) -> str:
        """Valida il nome del corso."""
        if not v or len(v) < 3 or len(v) > 200:
            raise ValueError('Nome corso deve essere 3-200 caratteri')
        return v

    @field_validator('isced_code')
    @classmethod
    def validate_isced_code(cls, v: str) -> str:
        """Valida il codice ISCED."""
        if not v or len(v) != 4 or not v.isdigit():
            raise ValueError('Codice ISCED deve essere 4 cifre')
        return v


class StudyPeriod(BaseModel):
    """Definisce il periodo di studio della credenziale."""
    start_date: datetime.datetime = Field(..., description="Data di inizio")
    end_date: datetime.datetime = Field(..., description="Data di fine")
    study_type: StudyType = Field(..., description="Tipologia di studio")
    academic_year: str = Field(..., description="Anno accademico (es. 2024/2025)")
    semester: Optional[str] = Field(None, description="Semestre specifico")

    @field_validator('academic_year')
    @classmethod
    def validate_academic_year(cls, v: str) -> str:
        """Valida il formato dell'anno accademico."""
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

    @model_validator(mode='after')
    def validate_dates(self) -> 'StudyPeriod':
        """Valida la coerenza delle date."""
        if self.start_date and self.end_date and self.start_date >= self.end_date:
            raise ValueError('Data fine deve essere successiva a data inizio')
        return self


class University(BaseModel):
    """Informazioni di un'università."""
    name: str = Field(..., description="Nome completo dell'università")
    country: str = Field(..., description="Codice paese ISO 2 lettere")
    erasmus_code: Optional[str] = Field(None, description="Codice Erasmus")
    website: Optional[str] = Field(None, description="Sito web ufficiale")
    address: Optional[str] = Field(None, description="Indirizzo postale")
    city: str = Field(..., description="Città sede")

    @field_validator('country')
    @classmethod
    def validate_country_code(cls, v: str) -> str:
        """Valida il codice paese ISO."""
        if not v or len(v) != 2 or not v.isalpha():
            raise ValueError('Codice paese deve essere 2 lettere ISO')
        return v.upper()

    @field_validator('erasmus_code')
    @classmethod
    def validate_erasmus_code(cls, v: Optional[str]) -> Optional[str]:
        """Valida il codice Erasmus se presente."""
        if v and (len(v) < 5 or len(v) > 15):
            raise ValueError('Codice Erasmus deve essere 5-15 caratteri')
        return v


class StudyProgram(BaseModel):
    """Informazioni sul programma di studio."""
    name: str = Field(..., description="Nome del programma")
    isced_code: str = Field(..., description="Codice ISCED del programma")
    eqf_level: EQFLevel = Field(..., description="Livello EQF")
    program_type: str = Field(..., description="Tipologia programma")
    field_of_study: str = Field(..., description="Campo di studio")

    @field_validator('name')
    @classmethod
    def validate_program_name(cls, v: str) -> str:
        """Valida il nome del programma."""
        if not v or len(v) < 5 or len(v) > 200:
            raise ValueError('Nome programma deve essere 5-200 caratteri')
        return v


class DigitalSignature(BaseModel):
    """Rappresenta una firma digitale applicata alla credenziale."""
    algorithm: str = Field(..., description="Algoritmo di firma utilizzato")
    value: str = Field(..., description="Valore della firma in Base64")
    timestamp: datetime.datetime = Field(..., description="Timestamp della firma")
    signer_certificate_thumbprint: Optional[str] = Field(
        None, description="Thumbprint del certificato del firmatario"
    )

    @field_validator('algorithm')
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        """Valida l'algoritmo di firma."""
        allowed_algorithms = [
            'RSA-SHA256-PSS', 'RSA-SHA256-PKCS1v15',
            'RSA-SHA384-PSS', 'RSA-SHA512-PSS'
        ]
        if v not in allowed_algorithms:
            raise ValueError(f'Algoritmo deve essere uno di: {allowed_algorithms}')
        return v


class Metadata(BaseModel):
    """Metadati della credenziale accademica."""
    version: str = Field(default="1.2", description="Versione formato credenziale")
    credential_id: UUID4 = Field(
        default_factory=uuid.uuid4, 
        description="Identificativo univoco della credenziale"
    )
    issued_at: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc), 
        description="Data e ora di emissione"
    )
    expires_at: Optional[datetime.datetime] = Field(None, description="Data di scadenza")
    merkle_root: str = Field(..., description="Radice del Merkle Tree per l'integrità")
    revocation_registry_url: Optional[str] = Field(
        None, description="URL del registro delle revoche"
    )
    revocation_id: Optional[str] = Field(None, description="ID per verifica revoca")

    @field_validator('version')
    @classmethod
    def validate_version(cls, v: str) -> str:
        """Valida la versione del formato."""
        if not v or v not in ['1.0', '1.1', '1.2']:
            raise ValueError('Versione deve essere 1.0, 1.1 o 1.2')
        return v

    @model_validator(mode='after')
    def validate_expiry(self) -> 'Metadata':
        """Valida la coerenza delle date di emissione e scadenza."""
        if self.issued_at and self.expires_at and self.expires_at <= self.issued_at:
            raise ValueError('Data scadenza deve essere successiva a data emissione')
        return self


class AcademicCredential(BaseModel):
    """
    Credenziale accademica completa.
    
    Rappresenta una credenziale digitale contenente tutti i dati
    relativi al percorso di studio di uno studente presso un'università.
    """
    metadata: Metadata = Field(..., description="Metadati della credenziale")
    issuer: University = Field(..., description="Università che emette la credenziale")
    subject: PersonalInfo = Field(..., description="Informazioni dello studente")
    study_period: StudyPeriod = Field(..., description="Periodo di studio")
    host_university: University = Field(..., description="Università ospitante")
    study_program: StudyProgram = Field(..., description="Programma di studio")
    courses: List[Course] = Field(..., min_length=1, description="Lista dei corsi sostenuti")
    total_ects_credits: int = Field(..., ge=0, description="Totale crediti ECTS")
    average_grade: Optional[str] = Field(None, description="Media dei voti")
    signature: Optional[DigitalSignature] = Field(None, description="Firma digitale")
    status: CredentialStatus = Field(
        default=CredentialStatus.DRAFT, 
        description="Stato della credenziale"
    )

    @model_validator(mode='after')
    def validate_academic_consistency(self) -> 'AcademicCredential':
        """Valida la coerenza accademica complessiva."""
        # Verifica coerenza crediti totali
        if self.courses:
            calculated_total = sum(course.ects_credits for course in self.courses)
            if self.total_ects_credits != calculated_total:
                raise ValueError(
                    f'Crediti totali ({self.total_ects_credits}) '
                    f'non corrispondono alla somma ({calculated_total})'
                )

        # Verifica che i corsi siano nel periodo di studio
        if self.study_period and self.courses:
            for course in self.courses:
                exam_date_utc = course.exam_date.astimezone(datetime.timezone.utc)
                start_date_utc = self.study_period.start_date.astimezone(datetime.timezone.utc)
                end_date_utc = self.study_period.end_date.astimezone(datetime.timezone.utc)
                
                if not (start_date_utc <= exam_date_utc <= end_date_utc):
                    raise ValueError(
                        f"L'esame '{course.course_name}' del {course.exam_date.date()} "
                        f"è fuori dal periodo di studio."
                    )
        
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Converte la credenziale in dizionario per serializzazione."""
        return self.model_dump(mode='json', exclude_none=False)

    def to_json(self, **kwargs) -> str:
        """Converte la credenziale in formato JSON."""
        return self.model_dump_json(exclude_none=False, indent=2, **kwargs)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AcademicCredential':
        """Crea un'istanza da dizionario."""
        return cls.model_validate(data)

    @classmethod
    def from_json(cls, json_str: str) -> 'AcademicCredential':
        """Crea un'istanza da stringa JSON."""
        return cls.model_validate_json(json_str)

    def calculate_merkle_root(self) -> str:
        """
        Calcola la radice del Merkle Tree dai dati dei corsi.
        
        Returns:
            Hash della radice del Merkle Tree
        """
        if not self.courses:
            return ""
        
        course_data = [course.model_dump(mode='json') for course in self.courses]
        merkle_tree = MerkleTree(course_data)
        return merkle_tree.get_merkle_root()
    
    def update_merkle_root(self) -> None:
        """Aggiorna la radice Merkle nei metadati."""
        self.metadata.merkle_root = self.calculate_merkle_root()

    def add_course(self, course: Course) -> None:
        """
        Aggiunge un corso e aggiorna i metadati correlati.
        
        Args:
            course: Corso da aggiungere
        """
        self.courses.append(course)
        self.total_ects_credits = sum(c.ects_credits for c in self.courses)
        self.update_merkle_root()

    def remove_course(self, course_code: str) -> bool:
        """
        Rimuove un corso identificato dal codice.
        
        Args:
            course_code: Codice del corso da rimuovere
            
        Returns:
            True se il corso è stato rimosso, False se non trovato
        """
        original_length = len(self.courses)
        self.courses = [c for c in self.courses if c.course_code != course_code]
        
        if len(self.courses) < original_length:
            self.total_ects_credits = sum(c.ects_credits for c in self.courses)
            self.update_merkle_root()
            return True
        
        return False

    def get_course_by_code(self, course_code: str) -> Optional[Course]:
        """
        Ottiene un corso specifico tramite il suo codice.
        
        Args:
            course_code: Codice del corso da cercare
            
        Returns:
            Corso trovato o None se non presente
        """
        return next((c for c in self.courses if c.course_code == course_code), None)

    def calculate_average_grade(self, target_system: GradeSystem = GradeSystem.ITALIAN_30) -> Optional[str]:
        """
        Calcola la media dei voti nel sistema specificato.
        
        Args:
            target_system: Sistema di valutazione per il calcolo della media
            
        Returns:
            Media calcolata come stringa o None se non calcolabile
        """
        if not self.courses:
            return None
        
        total_weighted = 0.0
        total_credits = 0
        
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
        """
        Converte un voto in formato numerico (sistema italiano 30/30).
        
        Args:
            grade: Voto da convertire
            
        Returns:
            Valore numerico del voto o None se non convertibile
        """
        try:
            if grade.grade_system == GradeSystem.ITALIAN_30:
                return (float(grade.score.split('/')[0]) 
                       if '/' in grade.score else float(grade.score))
            
            elif grade.grade_system == GradeSystem.ECTS_GRADE:
                ects_map = {'A': 30, 'B': 27, 'C': 24, 'D': 21, 'E': 18, 'F': 0}
                return float(ects_map.get(grade.score.upper(), 18))
            
            elif grade.grade_system == GradeSystem.FRENCH_20:
                french_grade = (float(grade.score.split('/')[0]) 
                              if '/' in grade.score else float(grade.score))
                return (french_grade / 20) * 30
            
            return None
            
        except (ValueError, AttributeError):
            return None

    def is_valid(self) -> Tuple[bool, List[str]]:
        """
        Verifica la validità complessiva della credenziale.
        
        Returns:
            Tupla con boolean di validità e lista di errori
        """
        errors = []
        
        # Verifica integrità Merkle Tree
        if self.metadata.merkle_root != self.calculate_merkle_root():
            errors.append("Integrità compromessa: Merkle root non corrispondente.")
        
        # Verifica scadenza
        if (self.metadata.expires_at and 
            datetime.datetime.now(datetime.timezone.utc) > self.metadata.expires_at):
            self.status = CredentialStatus.EXPIRED
            errors.append("Credenziale scaduta.")
        
        # Verifica stato
        if self.status in [CredentialStatus.REVOKED, CredentialStatus.SUSPENDED, 
                          CredentialStatus.EXPIRED]:
            errors.append(f"Credenziale non attiva (stato: {self.status.value}).")
        
        # Verifica firma per credenziali attive
        if self.status == CredentialStatus.ACTIVE and not self.signature:
            errors.append("Credenziale attiva ma priva di firma digitale.")
        
        return len(errors) == 0, errors

    def get_summary(self) -> Dict[str, Any]:
        """
        Genera un riassunto della credenziale per visualizzazione rapida.
        
        Returns:
            Dizionario con informazioni riassuntive
        """
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
            'expires_at': (self.metadata.expires_at.isoformat() 
                          if self.metadata.expires_at else None),
            'signed': self.signature is not None
        }


class CredentialFactory:
    """Factory per la creazione di credenziali accademiche."""
    
    @staticmethod
    def create_erasmus_credential(
        issuer_university: University,
        host_university: University,
        student_info: PersonalInfo,
        courses: List[Course],
        study_period: StudyPeriod,
        study_program: StudyProgram
    ) -> AcademicCredential:
        """
        Crea una credenziale Erasmus standard.
        
        Args:
            issuer_university: Università che emette la credenziale
            host_university: Università ospitante lo studente
            student_info: Dati dello studente
            courses: Lista dei corsi sostenuti
            study_period: Periodo di studio
            study_program: Programma di studio
            
        Returns:
            Credenziale Erasmus configurata
        """
        total_credits = sum(course.ects_credits for course in courses)
        
        metadata = Metadata(
            merkle_root="placeholder",  # Sarà calcolato dopo la creazione
            issued_at=datetime.datetime.now(datetime.timezone.utc)
        )
        
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
        
        # Aggiorna i metadati calcolati
        credential.update_merkle_root()
        credential.average_grade = credential.calculate_average_grade()
        
        return credential
    
    @staticmethod
    def create_sample_credential() -> AcademicCredential:
        """
        Crea una credenziale di esempio per testing.
        
        Returns:
            Credenziale di esempio completamente configurata
        """
        crypto_utils = CryptoUtils()
        
        # Università francese (emette la credenziale)
        univ_rennes = University(
            name="Université de Rennes", 
            country="FR", 
            erasmus_code="F RENNES01", 
            city="Rennes", 
            website="https://www.univ-rennes1.fr"
        )
        
        # Università italiana (ospita lo studente)
        univ_salerno = University(
            name="Università degli Studi di Salerno", 
            country="IT", 
            erasmus_code="I SALERNO01", 
            city="Fisciano", 
            website="https://www.unisa.it"
        )
        
        # Informazioni studente
        student_info = PersonalInfo(
            surname_hash=crypto_utils.sha256_hash_string("D'Aniello"), 
            name_hash=crypto_utils.sha256_hash_string("Mario"),
            birth_date_hash=crypto_utils.sha256_hash_string("1995-03-15"), 
            student_id_hash=crypto_utils.sha256_hash_string("0622702628"),
            pseudonym="student_mario_d'aniello"
        )
        
        # Periodo di studio
        study_period = StudyPeriod(
            start_date=datetime.datetime(2000, 9, 10, tzinfo=datetime.timezone.utc),
            end_date=datetime.datetime(2025, 9, 10, 23, 59, 59, tzinfo=datetime.timezone.utc),
            study_type=StudyType.ERASMUS, 
            academic_year="2000/2001"
        )
        
        # Programma di studio
        study_program = StudyProgram(
            name="Computer Science Exchange Program", 
            isced_code="0613", 
            eqf_level=EQFLevel.LEVEL_7,
            program_type="Master's Degree Exchange", 
            field_of_study="Computer Science"
        )
        
        # Corso di esempio
        course = Course(
            course_name="Ingegneria del software", 
            course_code="CRS-001", 
            isced_code="0613", 
            grade=ExamGrade(
                score="B", 
                passed=True, 
                grade_system=GradeSystem.ECTS_GRADE, 
                ects_grade="B"
            ), 
            exam_date=datetime.datetime(2024, 9, 10, 10, 0, tzinfo=datetime.timezone.utc), 
            ects_credits=6, 
            professor="Prof. Université de Rennes"
        )
        
        courses = [course]
        total_credits = sum(c.ects_credits for c in courses)
        metadata = Metadata(merkle_root="placeholder")
        
        credential = AcademicCredential(
            metadata=metadata, 
            issuer=univ_rennes,
            subject=student_info, 
            study_period=study_period,
            host_university=univ_salerno,
            study_program=study_program, 
            courses=courses,
            total_ects_credits=total_credits
        )
        
        credential.update_merkle_root()
        credential.average_grade = credential.calculate_average_grade()
        
        return credential