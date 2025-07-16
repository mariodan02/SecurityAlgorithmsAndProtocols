# Gestione Decentralizzata di Credenziali Accademiche

**Progetto per il corso di Algoritmi e Protocolli per la Sicurezza, A.A. 2024-2025**

Questo progetto implementa un sistema per l'emissione, la presentazione e la verifica di credenziali accademiche in modo decentralizzato, sicuro e rispettoso della privacy, come descritto nel contesto del programma Erasmus.

## Architettura del Sistema

Il sistema si basa su un'architettura a più componenti che interagiscono per garantire sicurezza e decentralizzazione:

1.  **Student Wallet**: Un'applicazione (simulata tramite script e interfaccia web) che permette allo studente di richiedere, conservare e presentare le proprie credenziali in modo selettivo.
2.  **Issuer (Università)**: L'entità (es. Università di Salerno) che emette le credenziali accademiche firmate digitalmente.
3.  **Verifier (Università Ospitante)**: L'entità (es. Université de Rennes) che riceve e verifica l'autenticità e la validità di una credenziale presentata da uno studente.
4.  **Certificate Authority (CA)**: Un'autorità di certificazione che emette e gestisce i certificati digitali X.509 per le università (Issuer e Verifier), garantendo la loro identità.
5.  **OCSP Responder**: Un servizio che risponde a richieste sullo stato di revoca dei certificati emessi dalla CA.
6.  **Blockchain (Simulata)**: Un registro pubblico e immutabile (simulato tramite un server Python) che traccia l'hash di ogni credenziale emessa e il suo stato (valido/revocato).

## Struttura del Repository


src/
├── blockchain/
│   ├── blockchain_client.py
│   └── smart_contract_logic.py   # Logica del contratto simulato
├── communication/
│   └── secure_server.py          # Server web principale (Flask)
├── credentials/
│   ├── issuer.py
│   ├── validator.py
│   └── models.py
├── crypto/
│   └── foundations.py
├── monitoring/
│   └── security_monitoring.py    # Modulo di monitoraggio
├── pki/
│   ├── certificate_authority.py
│   ├── certificate_manager.py
│   ├── ocsp_client.py
│   └── ocsp_responder.py         # Server per risposte OCSP
├── testing/
│   └── end_to_end_testing.py
├── verification/
│   └── verification_engine.py
├── wallet/
│   └── student_wallet.py
├── web/
│   ├── dashboard.py              # Logica delle route Flask
│   ├── static/
│   └── templates/
├── requirements.txt
└── security_events.log           # File di log generato dal monitor


## Setup e Installazione

1.  **Clonare il repository:**
    ```bash
    git clone <URL_DEL_REPOSITORY>
    cd <NOME_CARTELLA>/src
    ```

2.  **Creare un ambiente virtuale (consigliato):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # Su Windows: venv\Scripts\activate
    ```

3.  **Installare le dipendenze:**
    ```bash
    pip install -r requirements.txt
    ```

## Avvio del Sistema

Per eseguire il sistema completo, è necessario avviare i diversi server in terminali separati.

1.  **Avviare la Certificate Authority (se necessario per generare i certificati):**
    Eseguire gli script per creare la CA e i certificati per le università, se non già presenti.
    ```bash
    python -m pki.certificate_authority
    ```

2.  **Avviare il Responder OCSP:**
    Questo server gestisce le richieste di validità dei certificati.
    ```bash
    python -m pki.ocsp_responder
    ```
    *Il server sarà in ascolto su `http://127.0.0.1:5001`.*

3.  **Avviare il Server Web Principale:**
    Questo server contiene l'interfaccia web per tutte le operazioni (wallet, issuer, verifier).
    ```bash
    python -m communication.secure_server
    ```
    *Il server sarà in ascolto su `https://127.0.0.1:8080`.*

Una volta avviati tutti i componenti, è possibile accedere all'interfaccia web all'indirizzo `https://127.0.0.1:8080` per interagire con il sistema.

## Esecuzione dei Test

Per verificare la correttezza del flusso end-to-end, è possibile eseguire lo script di test. Assicurarsi che tutti i server siano in esecuzione prima di lanciare i test.
```bash
python -m testing.end_to_end_testing

