# Progetto di Algoritmi e Protocolli per la Sicurezza - Gruppo 19

## Sistema decentralizzato di gestione credenziali accademiche

Questo progetto implementa un sistema decentralizzato per l'emissione, la gestione e la verifica di credenziali accademiche, basato su un'architettura a chiave pubblica (PKI), firme digitali, Merkle Tree per la divulgazione selettiva e prevede un'integrazione con una blockchain per la gestione delle revoche.

### Funzionalità Principali

* **Infrastruttura a Chiave Pubblica (PKI):** Una Certificate Authority (CA) dedicata per generare e firmare i certificati digitali per tutte le entità del sistema (università, studenti, server).
* **Emissione e Validazione di Credenziali:** Le università possono emettere credenziali accademiche digitali (Transcript of Records) firmate digitalmente per garantirne l'autenticità e l'integrità.
* **Wallet Digitale per Studenti:** Gli studenti possono conservare e gestire in modo sicuro le proprie credenziali in un wallet digitale crittografato.
* **Divulgazione Selettiva (Selective Disclosure):** Grazie all'uso di Merkle Tree, gli studenti possono creare "presentazioni" delle proprie credenziali, condividendo solo le informazioni strettamente necessarie senza invalidare la firma digitale dell'intera credenziale.
* **Integrazione Blockchain:** Lo stato delle credenziali (es. revoca) viene registrato su una blockchain (simulata con Ganache), garantendo un registro immutabile e decentralizzato.
* **Comunicazione Sicura:** Tutte le comunicazioni tra i componenti del sistema avvengono tramite un server API sicuro che utilizza TLS per la cifratura del traffico di rete.
* **Dashboard Web:** Un'interfaccia web multi-ruolo (issuer, verifier, studente) per interagire con il sistema in modo intuitivo.

### Architettura del Sistema

Il sistema è composto dai seguenti macro-componenti:

1.  **Web dashboard (`/src/web`):** L'interfaccia utente basata su FastAPI che permette a studenti, università emittenti e università verificatrici di interagire con il sistema.
2.  **Server (`/src/communication`):** Un server API che gestisce la comunicazione sicura tra i vari componenti e integra le API per l'interazione con la blockchain.
3.  **PKI e crittografia (`/src/pki`, `/src/crypto`):** Infrastruttura a chiave pubblica che include la CA, la gestione dei certificati, il client OCSP per la verifica delle revoche e le fondamenta crittografiche (RSA, firme digitali, Merkle Tree).
4.  **Gestione credenziali (`/src/credentials`):** Contiene i modelli dati per le credenziali, la logica per la loro emissione da parte delle università e la loro validazione.
5.  **Wallet studente (`/src/wallet`):** Implementa il wallet digitale per gli studenti, la logica per la divulgazione selettiva e la creazione di presentazioni verificabili.
6.  **Integrazione blockchain (`/src/blockchain`):** Contiene lo smart contract in solidity e il servizio python per interagire con la blockchain per la registrazione e la revoca delle credenziali.

### Guida Rapida all'Avvio

#### Prerequisiti

* Python
* Node.js e npm (per la compilazione e il deploy dello smart contract)
* Ganache (per la simulazione della blockchain)
* Aver installato le dipendenze Python con `pip install -r requirements.txt`

#### Passaggi per l'Avvio

1.  **Avviare Ganache:**
    Assicurarsi che Ganache sia in esecuzione e in ascolto sulla porta `8545` (abbiamo supposto Ganache in esecuzione da CLI). È consigliabile avviarlo con un bilancio elevato per gli account di test:
    ```sh
    ganache -e 2000000000000000
    ```

2.  **Compilare e Distribuire lo Smart Contract:**
    Posizionarsi nella directory `src/blockchain` ed eseguire i seguenti comandi:
    ```sh
    npm install
    node compile.js
    node deploy.js
    ```

3.  **Configurare la Chiave Privata per la Blockchain:**
    Aprire il file `src/blockchain/blockchain_service.py` e sostituire il valore della variabile `GANACHE_BANKER_KEY` con una delle chiavi private fornite da Ganache.


4.  **Generare i Certificati Digitali:**
    Eseguire lo script della Certificate Authority per generare tutti i certificati necessari per le entità del sistema:
    ```sh
    python src/pki/certificate_authority.py
    ```

5.  **Avviare il Sistema:**
    Tornare nella directory principale del progetto ed eseguire lo script principale:
    ```sh
    python run_system.py
    ```
A questo punto, l'intero sistema sarà in esecuzione.

### Utilizzo del Sistema

#### 1. ✅ Accettare il Certificato Self-Signed (Passaggio Obbligatorio)

* Prima di usare la dashboard, è necessario aprire una nuova scheda del browser e andare su **[https://localhost:8443/](https://localhost:8443/)**.
* Il browser mostrerà un avviso di sicurezza. Questo è normale perché il server usa un certificato autofirmato che non è riconosciuto da un'autorità pubblica.
* Clicca su **"Avanzate"** e poi su **"Procedi su localhost (non sicuro)"**.
* **Questo passaggio è fondamentale.** Se non lo fai, la Dashboard (`http://localhost:8000`) non potrà comunicare con il server sicuro e le operazioni (specialmente quelle sulla blockchain) falliranno con un errore di rete (`Fetch network error`).

#### 2. Accedere alla Dashboard

* Una volta accettato il certificato, puoi usare l'applicazione navigando all'indirizzo: **[http://localhost:8000](http://localhost:8000)**.

#### Utenti Demo

Per accedere alla dashboard, è possibile utilizzare i seguenti utenti di prova (la password per tutti è `Unisa2025`):

* `issuer_rennes`: Università che può emettere credenziali.
* `verifier_unisa`: Università che può verificare le presentazioni.
* `studente_mariorossi`: Studente che può gestire il proprio wallet e creare presentazioni.