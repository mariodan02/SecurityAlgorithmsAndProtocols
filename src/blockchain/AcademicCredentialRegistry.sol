# =============================================================================
# FASE 6: REGISTRO REVOCHE - SMART CONTRACT
# File: blockchain/contracts/AcademicCredentialRegistry.sol
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AcademicCredentialRegistry
 * @dev Smart contract per la gestione decentralizzata dello stato delle credenziali accademiche
 * @author Sistema Credenziali Accademiche Decentralizzate
 */
contract AcademicCredentialRegistry {
    
    // =============================================================================
    // STRUTTURE DATI
    // =============================================================================
    
    /**
     * @dev Stati possibili di una credenziale
     */
    enum CredentialStatus {
        NOT_ISSUED,     // 0 - Non ancora emessa
        ACTIVE,         // 1 - Attiva
        REVOKED,        // 2 - Revocata
        SUSPENDED,      // 3 - Sospesa
        EXPIRED         // 4 - Scaduta
    }
    
    /**
     * @dev Motivi di revoca standardizzati
     */
    enum RevocationReason {
        NONE,                    // 0 - Nessuna revoca
        ADMINISTRATIVE_ERROR,    // 1 - Errore amministrativo
        FRAUDULENT_ACTIVITY,     // 2 - Attività fraudolenta
        STUDENT_REQUEST,         // 3 - Richiesta studente
        UNIVERSITY_POLICY,       // 4 - Politica università
        EXPIRED_CREDENTIALS,     // 5 - Credenziali scadute
        SYSTEM_MAINTENANCE,      // 6 - Manutenzione sistema
        LEGAL_REQUIREMENT        // 7 - Requisito legale
    }
    
    /**
     * @dev Informazioni complete su una credenziale
     */
    struct CredentialInfo {
        bytes32 credentialId;           // ID univoco credenziale
        address issuerAddress;          // Indirizzo università emittente
        address studentAddress;         // Indirizzo studente (opzionale)
        bytes32 merkleRoot;            // Radice Merkle Tree della credenziale
        CredentialStatus status;        // Stato attuale
        uint256 issuedTimestamp;       // Timestamp emissione
        uint256 expirationTimestamp;   // Timestamp scadenza (0 = non scade)
        uint256 revokedTimestamp;      // Timestamp revoca (0 = non revocata)
        RevocationReason revocationReason; // Motivo revoca
        string metadataURI;            // URI ai metadati aggiuntivi
        bool exists;                   // Flag esistenza
    }
    
    /**
     * @dev Informazioni università autorizzata
     */
    struct UniversityInfo {
        string name;                   // Nome università
        string country;                // Paese
        bool isAuthorized;            // Autorizzata ad emettere
        uint256 totalCredentialsIssued; // Totale credenziali emesse
        uint256 registrationTimestamp; // Data registrazione
        bytes32 certificateHash;       // Hash certificato X.509
    }
    
    // =============================================================================
    // STORAGE VARIABILI
    // =============================================================================
    
    /// @dev Owner del contratto (Certificate Authority)
    address public owner;
    
    /// @dev Versione del contratto
    string public constant VERSION = "1.0.0";
    
    /// @dev Nome del registro
    string public constant REGISTRY_NAME = "Academic Credential Registry";
    
    /// @dev Mapping credentialId => CredentialInfo
    mapping(bytes32 => CredentialInfo) public credentials;
    
    /// @dev Mapping università address => UniversityInfo
    mapping(address => UniversityInfo) public universities;
    
    /// @dev Array di tutti gli ID credenziali per iterazione
    bytes32[] public credentialIds;
    
    /// @dev Array di tutte le università registrate
    address[] public universityAddresses;
    
    /// @dev Mapping per verifiche rapide di esistenza
    mapping(bytes32 => bool) public credentialExists;
    mapping(address => bool) public universityExists;
    
    /// @dev Contatori statistiche
    uint256 public totalCredentials;
    uint256 public totalUniversities;
    uint256 public totalRevocations;
    
    // =============================================================================
    // EVENTI
    // =============================================================================
    
    /**
     * @dev Emesso quando una nuova credenziale viene registrata
     */
    event CredentialIssued(
        bytes32 indexed credentialId,
        address indexed issuer,
        address indexed student,
        bytes32 merkleRoot,
        uint256 timestamp
    );
    
    /**
     * @dev Emesso quando una credenziale viene revocata
     */
    event CredentialRevoked(
        bytes32 indexed credentialId,
        address indexed issuer,
        RevocationReason reason,
        uint256 timestamp
    );
    
    /**
     * @dev Emesso quando lo stato di una credenziale cambia
     */
    event CredentialStatusChanged(
        bytes32 indexed credentialId,
        CredentialStatus oldStatus,
        CredentialStatus newStatus,
        uint256 timestamp
    );
    
    /**
     * @dev Emesso quando una università viene registrata
     */
    event UniversityRegistered(
        address indexed universityAddress,
        string name,
        string country,
        uint256 timestamp
    );
    
    /**
     * @dev Emesso quando una università viene autorizzata/disautorizzata
     */
    event UniversityAuthorizationChanged(
        address indexed universityAddress,
        bool authorized,
        uint256 timestamp
    );
    
    // =============================================================================
    // MODIFICATORI
    // =============================================================================
    
    /**
     * @dev Solo il proprietario del contratto può eseguire
     */
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can perform this action");
        _;
    }
    
    /**
     * @dev Solo università autorizzate possono eseguire
     */
    modifier onlyAuthorizedUniversity() {
        require(
            universityExists[msg.sender] && universities[msg.sender].isAuthorized,
            "Only authorized universities can perform this action"
        );
        _;
    }
    
    /**
     * @dev Verifica che la credenziale esista
     */
    modifier credentialMustExist(bytes32 credentialId) {
        require(credentialExists[credentialId], "Credential does not exist");
        _;
    }
    
    /**
     * @dev Verifica che la credenziale non esista già
     */
    modifier credentialMustNotExist(bytes32 credentialId) {
        require(!credentialExists[credentialId], "Credential already exists");
        _;
    }
    
    // =============================================================================
    // CONSTRUCTOR
    // =============================================================================
    
    /**
     * @dev Costruttore del contratto
     */
    constructor() {
        owner = msg.sender;
        totalCredentials = 0;
        totalUniversities = 0;
        totalRevocations = 0;
    }
    
    // =============================================================================
    // FUNZIONI PUBBLICHE - GESTIONE UNIVERSITÀ
    // =============================================================================
    
    /**
     * @dev Registra una nuova università nel sistema
     * @param universityAddress Indirizzo Ethereum dell'università
     * @param name Nome dell'università
     * @param country Paese dell'università
     * @param certificateHash Hash del certificato X.509
     */
    function registerUniversity(
        address universityAddress,
        string calldata name,
        string calldata country,
        bytes32 certificateHash
    ) external onlyOwner {
        require(universityAddress != address(0), "Invalid university address");
        require(bytes(name).length > 0, "University name cannot be empty");
        require(bytes(country).length == 2, "Country must be 2-letter code");
        require(!universityExists[universityAddress], "University already registered");
        
        universities[universityAddress] = UniversityInfo({
            name: name,
            country: country,
            isAuthorized: true,  // Autorizzata di default alla registrazione
            totalCredentialsIssued: 0,
            registrationTimestamp: block.timestamp,
            certificateHash: certificateHash
        });
        
        universityExists[universityAddress] = true;
        universityAddresses.push(universityAddress);
        totalUniversities++;
        
        emit UniversityRegistered(universityAddress, name, country, block.timestamp);
        emit UniversityAuthorizationChanged(universityAddress, true, block.timestamp);
    }
    
    /**
     * @dev Autorizza o disautorizza una università
     * @param universityAddress Indirizzo dell'università
     * @param authorized True per autorizzare, false per disautorizzare
     */
    function setUniversityAuthorization(address universityAddress, bool authorized) 
        external 
        onlyOwner 
    {
        require(universityExists[universityAddress], "University not registered");
        require(
            universities[universityAddress].isAuthorized != authorized,
            "Authorization status already set"
        );
        
        universities[universityAddress].isAuthorized = authorized;
        
        emit UniversityAuthorizationChanged(universityAddress, authorized, block.timestamp);
    }
    
    // =============================================================================
    // FUNZIONI PUBBLICHE - GESTIONE CREDENZIALI
    // =============================================================================
    
    /**
     * @dev Registra una nuova credenziale emessa
     * @param credentialId ID univoco della credenziale
     * @param studentAddress Indirizzo studente (opzionale, può essere 0x0)
     * @param merkleRoot Radice Merkle Tree della credenziale
     * @param expirationTimestamp Timestamp scadenza (0 = non scade)
     * @param metadataURI URI ai metadati aggiuntivi
     */
    function issueCredential(
        bytes32 credentialId,
        address studentAddress,
        bytes32 merkleRoot,
        uint256 expirationTimestamp,
        string calldata metadataURI
    ) external onlyAuthorizedUniversity credentialMustNotExist(credentialId) {
        require(credentialId != bytes32(0), "Invalid credential ID");
        require(merkleRoot != bytes32(0), "Invalid Merkle root");
        require(
            expirationTimestamp == 0 || expirationTimestamp > block.timestamp,
            "Expiration must be in the future"
        );
        
        credentials[credentialId] = CredentialInfo({
            credentialId: credentialId,
            issuerAddress: msg.sender,
            studentAddress: studentAddress,
            merkleRoot: merkleRoot,
            status: CredentialStatus.ACTIVE,
            issuedTimestamp: block.timestamp,
            expirationTimestamp: expirationTimestamp,
            revokedTimestamp: 0,
            revocationReason: RevocationReason.NONE,
            metadataURI: metadataURI,
            exists: true
        });
        
        credentialExists[credentialId] = true;
        credentialIds.push(credentialId);
        totalCredentials++;
        
        // Incrementa contatore università
        universities[msg.sender].totalCredentialsIssued++;
        
        emit CredentialIssued(credentialId, msg.sender, studentAddress, merkleRoot, block.timestamp);
    }
    
    /**
     * @dev Revoca una credenziale esistente
     * @param credentialId ID della credenziale da revocare
     * @param reason Motivo della revoca
     */
    function revokeCredential(bytes32 credentialId, RevocationReason reason)
        external
        onlyAuthorizedUniversity
        credentialMustExist(credentialId)
    {
        CredentialInfo storage credential = credentials[credentialId];
        
        require(credential.issuerAddress == msg.sender, "Only issuer can revoke credential");
        require(credential.status == CredentialStatus.ACTIVE, "Credential must be active to revoke");
        require(reason != RevocationReason.NONE, "Must provide revocation reason");
        
        CredentialStatus oldStatus = credential.status;
        credential.status = CredentialStatus.REVOKED;
        credential.revokedTimestamp = block.timestamp;
        credential.revocationReason = reason;
        
        totalRevocations++;
        
        emit CredentialRevoked(credentialId, msg.sender, reason, block.timestamp);
        emit CredentialStatusChanged(credentialId, oldStatus, CredentialStatus.REVOKED, block.timestamp);
    }
    
    /**
     * @dev Sospende temporaneamente una credenziale
     * @param credentialId ID della credenziale da sospendere
     */
    function suspendCredential(bytes32 credentialId)
        external
        onlyAuthorizedUniversity
        credentialMustExist(credentialId)
    {
        CredentialInfo storage credential = credentials[credentialId];
        
        require(credential.issuerAddress == msg.sender, "Only issuer can suspend credential");
        require(credential.status == CredentialStatus.ACTIVE, "Credential must be active to suspend");
        
        CredentialStatus oldStatus = credential.status;
        credential.status = CredentialStatus.SUSPENDED;
        
        emit CredentialStatusChanged(credentialId, oldStatus, CredentialStatus.SUSPENDED, block.timestamp);
    }
    
    /**
     * @dev Riattiva una credenziale sospesa
     * @param credentialId ID della credenziale da riattivare
     */
    function reactivateCredential(bytes32 credentialId)
        external
        onlyAuthorizedUniversity
        credentialMustExist(credentialId)
    {
        CredentialInfo storage credential = credentials[credentialId];
        
        require(credential.issuerAddress == msg.sender, "Only issuer can reactivate credential");
        require(credential.status == CredentialStatus.SUSPENDED, "Credential must be suspended to reactivate");
        
        // Verifica che non sia scaduta nel frattempo
        if (credential.expirationTimestamp > 0 && block.timestamp >= credential.expirationTimestamp) {
            credential.status = CredentialStatus.EXPIRED;
            emit CredentialStatusChanged(credentialId, CredentialStatus.SUSPENDED, CredentialStatus.EXPIRED, block.timestamp);
        } else {
            CredentialStatus oldStatus = credential.status;
            credential.status = CredentialStatus.ACTIVE;
            emit CredentialStatusChanged(credentialId, oldStatus, CredentialStatus.ACTIVE, block.timestamp);
        }
    }
    
    // =============================================================================
    // FUNZIONI VIEW - QUERY PUBBLICHE
    // =============================================================================
    
    /**
     * @dev Ottiene lo stato di una credenziale
     * @param credentialId ID della credenziale
     * @return status Stato attuale della credenziale
     */
    function getCredentialStatus(bytes32 credentialId) 
        external 
        view 
        credentialMustExist(credentialId) 
        returns (CredentialStatus status) 
    {
        CredentialInfo memory credential = credentials[credentialId];
        
        // Controlla scadenza automatica
        if (credential.expirationTimestamp > 0 && block.timestamp >= credential.expirationTimestamp) {
            return CredentialStatus.EXPIRED;
        }
        
        return credential.status;
    }
    
    /**
     * @dev Ottiene informazioni complete su una credenziale
     * @param credentialId ID della credenziale
     * @return info Informazioni complete della credenziale
     */
    function getCredentialInfo(bytes32 credentialId)
        external
        view
        credentialMustExist(credentialId)
        returns (CredentialInfo memory info)
    {
        return credentials[credentialId];
    }
    
    /**
     * @dev Verifica se una credenziale è valida (attiva e non scaduta)
     * @param credentialId ID della credenziale
     * @return isValid True se la credenziale è valida
     */
    function isCredentialValid(bytes32 credentialId) 
        external 
        view 
        credentialMustExist(credentialId) 
        returns (bool isValid) 
    {
        CredentialInfo memory credential = credentials[credentialId];
        
        // Deve essere attiva
        if (credential.status != CredentialStatus.ACTIVE) {
            return false;
        }
        
        // Non deve essere scaduta
        if (credential.expirationTimestamp > 0 && block.timestamp >= credential.expirationTimestamp) {
            return false;
        }
        
        return true;
    }
    
    /**
     * @dev Verifica se una università è autorizzata
     * @param universityAddress Indirizzo dell'università
     * @return isAuthorized True se autorizzata
     */
    function isUniversityAuthorized(address universityAddress) 
        external 
        view 
        returns (bool isAuthorized) 
    {
        return universityExists[universityAddress] && universities[universityAddress].isAuthorized;
    }
    
    /**
     * @dev Ottiene informazioni su una università
     * @param universityAddress Indirizzo dell'università
     * @return info Informazioni dell'università
     */
    function getUniversityInfo(address universityAddress)
        external
        view
        returns (UniversityInfo memory info)
    {
        require(universityExists[universityAddress], "University not registered");
        return universities[universityAddress];
    }
    
    /**
     * @dev Ottiene statistiche generali del registro
     * @return _totalCredentials Totale credenziali registrate
     * @return _totalUniversities Totale università registrate
     * @return _totalRevocations Totale revoche effettuate
     * @return _activeCredentials Credenziali attualmente attive
     */
    function getRegistryStatistics() 
        external 
        view 
        returns (
            uint256 _totalCredentials,
            uint256 _totalUniversities, 
            uint256 _totalRevocations,
            uint256 _activeCredentials
        ) 
    {
        uint256 activeCount = 0;
        
        for (uint256 i = 0; i < credentialIds.length; i++) {
            CredentialInfo memory cred = credentials[credentialIds[i]];
            if (cred.status == CredentialStatus.ACTIVE) {
                // Controlla se non è scaduta
                if (cred.expirationTimestamp == 0 || block.timestamp < cred.expirationTimestamp) {
                    activeCount++;
                }
            }
        }
        
        return (totalCredentials, totalUniversities, totalRevocations, activeCount);
    }
    
    /**
     * @dev Ottiene lista paginata di credenziali
     * @param offset Offset di partenza
     * @param limit Numero massimo di risultati
     * @return credentialIdList Lista ID credenziali
     * @return hasMore True se ci sono più risultati
     */
    function getCredentialsPaginated(uint256 offset, uint256 limit)
        external
        view
        returns (bytes32[] memory credentialIdList, bool hasMore)
    {
        require(limit > 0 && limit <= 100, "Limit must be between 1 and 100");
        
        if (offset >= credentialIds.length) {
            return (new bytes32[](0), false);
        }
        
        uint256 end = offset + limit;
        if (end > credentialIds.length) {
            end = credentialIds.length;
        }
        
        bytes32[] memory result = new bytes32[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            result[i - offset] = credentialIds[i];
        }
        
        hasMore = end < credentialIds.length;
        return (result, hasMore);
    }
    
    // =============================================================================
    // FUNZIONI AMMINISTRATIVE
    // =============================================================================
    
    /**
     * @dev Trasferisce la proprietà del contratto
     * @param newOwner Nuovo proprietario
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        require(newOwner != owner, "New owner must be different");
        
        owner = newOwner;
    }
    
    /**
     * @dev Funzione di emergenza per aggiornare batch di credenziali scadute
     * @param credentialIdList Lista ID credenziali da verificare
     */
    function updateExpiredCredentials(bytes32[] calldata credentialIdList) external {
        for (uint256 i = 0; i < credentialIdList.length; i++) {
            bytes32 credId = credentialIdList[i];
            
            if (credentialExists[credId]) {
                CredentialInfo storage credential = credentials[credId];
                
                if (credential.status == CredentialStatus.ACTIVE &&
                    credential.expirationTimestamp > 0 &&
                    block.timestamp >= credential.expirationTimestamp) {
                    
                    CredentialStatus oldStatus = credential.status;
                    credential.status = CredentialStatus.EXPIRED;
                    
                    emit CredentialStatusChanged(credId, oldStatus, CredentialStatus.EXPIRED, block.timestamp);
                }
            }
        }
    }
    
    /**
     * @dev Verifica integrità di una credenziale tramite Merkle root
     * @param credentialId ID della credenziale
     * @param expectedMerkleRoot Merkle root atteso
     * @return matches True se il Merkle root corrisponde
     */
    function verifyCredentialIntegrity(bytes32 credentialId, bytes32 expectedMerkleRoot)
        external
        view
        credentialMustExist(credentialId)
        returns (bool matches)
    {
        return credentials[credentialId].merkleRoot == expectedMerkleRoot;
    }
}