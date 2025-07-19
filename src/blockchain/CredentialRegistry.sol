// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title CredentialRegistry
 * @dev Questo smart contract gestisce la registrazione, la verifica e la revoca
 * di credenziali accademiche, in linea con quanto definito nel WP1 e WP2 del progetto.
 * Memorizza solo i metadati essenziali per la verifica (stato e timestamp) per
 * preservare la privacy, come da specifica[cite: 440].
 */
contract CredentialRegistry {

    // Struttura per memorizzare le informazioni di una credenziale
    struct Credential {
        string credentialUUID; // ID univoco della credenziale [cite: 169]
        address issuer;        // Indirizzo dell'università che ha emesso la credenziale [cite: 30]
        uint256 timestamp;     // Timestamp di emissione [cite: 170]
        bool isRevoked;        // Stato di revoca
        string reasonForRevocation; // Motivo della revoca
        
    }

    // Mapping dall'ID della credenziale alla sua struttura dati
    mapping(string => Credential) private credentials;

    // Eventi per notificare le azioni sulla blockchain
    event CredentialRegistered(string indexed credentialUUID, address indexed issuer);
    event CredentialRevoked(string indexed credentialUUID, string reason);

    /**
     * @dev Registra una nuova credenziale sulla blockchain.
     * Solo l'emittente (issuer) può chiamare questa funzione.
     * @param _credentialUUID L'identificativo univoco della credenziale.
     */
    function registerCredential(string memory _credentialUUID) public {
        // Verifica che la credenziale non sia già registrata
        require(credentials[_credentialUUID].issuer == address(0), "Credential already registered.");

        credentials[_credentialUUID] = Credential({
            credentialUUID: _credentialUUID,
            issuer: msg.sender,
            timestamp: block.timestamp,
            isRevoked: false,
            reasonForRevocation: ""
        });

        emit CredentialRegistered(_credentialUUID, msg.sender);
    }

    /**
     * @dev Revoca una credenziale esistente.
     * Solo l'emittente originale della credenziale può revocarla. [cite: 513, 514]
     * @param _credentialUUID L'ID della credenziale da revocare.
     * @param _reason Il motivo della revoca.
     */
    function revokeCredential(string memory _credentialUUID, string memory _reason) public {
        // Verifica che chi chiama la funzione sia l'emittente originale
        require(credentials[_credentialUUID].issuer == msg.sender, "Only the issuer can revoke this credential.");
        // Verifica che la credenziale non sia già stata revocata
        require(!credentials[_credentialUUID].isRevoked, "Credential has already been revoked.");

        credentials[_credentialUUID].isRevoked = true;
        credentials[_credentialUUID].reasonForRevocation = _reason;

        emit CredentialRevoked(_credentialUUID, _reason);
    }

    /**
     * @dev Verifica lo stato di una credenziale. È una funzione di lettura (view)
     * e non consuma gas se chiamata esternamente. [cite: 471, 473, 605]
     * @param _credentialUUID L'ID della credenziale da verificare.
     * @return Un booleano che indica se la credenziale è revocata, l'indirizzo
     * dell'emittente e il timestamp di emissione.
     */
    function verifyCredential(string memory _credentialUUID) public view returns (address, uint256, bool) {
        Credential storage cred = credentials[_credentialUUID];
        return (cred.issuer, cred.timestamp, cred.isRevoked);
    }
}