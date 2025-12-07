# Security Algorithms and Protocols Project - Group 19

## Decentralized Academic Credential Management System

This project implements a decentralized system for issuing, managing, and verifying academic credentials. It is based on a Public Key Infrastructure (PKI), digital signatures, Merkle Trees for selective disclosure, and includes blockchain integration for revocation management.

### Key Features

  * **Public Key Infrastructure (PKI):** A dedicated Certificate Authority (CA) to generate and sign digital certificates for all system entities (universities, students, servers).
  * **Credential Issuance and Validation:** Universities can issue digital academic credentials (Transcript of Records) that are digitally signed to ensure authenticity and integrity.
  * **Student Digital Wallet:** Students can securely store and manage their credentials in an encrypted digital wallet.
  * **Selective Disclosure:** Utilizing Merkle Trees, students can create "presentations" of their credentials, sharing only the strictly necessary information without invalidating the digital signature of the entire credential.
  * **Blockchain Integration:** Credential status (e.g., revocation) is recorded on a blockchain (simulated with Ganache), ensuring an immutable and decentralized registry.
  * **Secure Communication:** All communications between system components occur via a secure API server using TLS for network traffic encryption.
  * **Web Dashboard:** A multi-role web interface (issuer, verifier, student) for intuitive system interaction.

### System Architecture

The system consists of the following macro-components:

1.  **Web Dashboard (`/src/web`):** The FastAPI-based user interface allowing students, issuing universities, and verifying universities to interact with the system.
2.  **Server (`/src/communication`):** A secure API server managing communication between components and integrating APIs for blockchain interaction.
3.  **PKI and Cryptography (`/src/pki`, `/src/crypto`):** PKI infrastructure including the CA, certificate management, OCSP client for revocation verification, and cryptographic foundations (RSA, digital signatures, Merkle Trees).
4.  **Credential Management (`/src/credentials`):** Contains data models for credentials, logic for their issuance by universities, and their validation.
5.  **Student Wallet (`/src/wallet`):** Implements the digital wallet for students, logic for selective disclosure, and the creation of verifiable presentations.
6.  **Blockchain Integration (`/src/blockchain`):** Contains the Solidity smart contract and the Python service for interacting with the blockchain for credential registration and revocation.

#### Architecture Designed for Microservices Containerization

The current architecture uses Python threads to orchestrate components (Dashboard, API Server, OCSP Responder) in a single process via `run_system.py`. This solution is ideal for development and local demos.

**For a production environment**, it is recommended to:

  - **Containerize each component** in separate Docker containers (Dashboard, API Server, OCSP Responder, Blockchain Node).
  - **Use Docker Compose** or Kubernetes for microservices orchestration.
  - **Separate concerns**: each service can scale independently based on load.
  - **Implement service discovery** and load balancing between microservices.
  - **Manage secrets** with dedicated systems (HashiCorp Vault, AWS Secrets Manager, Kubernetes Secrets).
  - **Centralized monitoring and logging** (Prometheus, Grafana, ELK Stack).

The project's modular architecture facilitates this transition to containerized microservices without requiring significant code refactoring.

### Quick Start Guide

#### Prerequisites

  * Python
  * Node.js and npm (for compiling and deploying the smart contract)
  * Ganache (for blockchain simulation)
  * Python dependencies installed via `pip install -r requirements.txt`

#### Steps to Start

1.  **Start Ganache:**
    Ensure Ganache is running and listening on port `8545` (assuming Ganache CLI execution). It is advisable to start it with a high balance for test accounts:

    ```sh
    ganache -e 2000000000000000
    ```

2.  **Compile and Deploy the Smart Contract:**
    Navigate to the `src/blockchain` directory and execute the following commands:

    ```sh
    npm install
    node compile.js
    node deploy.js
    ```

3.  **Configure Environment Variables:**
    Copy the `.env.example` file to `.env` and configure the necessary variables:

    ```sh
    cp .env.example .env
    ```

    Edit the `.env` file and replace `GANACHE_BANKER_KEY` with one of the private keys provided by Ganache at startup.

4.  **Generate Digital Certificates:**
    Run the Certificate Authority script to generate all necessary certificates for system entities:

    ```sh
    python src/pki/certificate_authority.py
    ```

5.  **Start the System:**
    Return to the project's root directory and run the main script:

    ```sh
    python run_system.py
    ```

    At this point, the entire system will be up and running.

### Using the System

#### 1\. ✅ Accept the Self-Signed Certificate (Mandatory Step)

  * Before using the dashboard, you must open a new browser tab and go to **[https://localhost:8443/](https://www.google.com/search?q=https://localhost:8443/)**.
  * The browser will display a security warning. This is normal because the server uses a self-signed certificate not recognized by a public authority.
  * Click on **"Advanced"** and then on **"Proceed to localhost (unsafe)"**.
  * **This step is crucial.** If skipped, the Dashboard (`http://localhost:8000`) will not be able to communicate with the secure server, and operations (especially those on the blockchain) will fail with a network error (`Fetch network error`).

#### 2\. Access the Dashboard

  * Once the certificate is accepted, you can use the application by navigating to: **[http://localhost:8000](https://www.google.com/search?q=http://localhost:8000)**.

#### Demo Users

To access the dashboard, you can use the following test users (the password for all is `Unisa2025`):

  * `issuer_rennes`: University that can issue credentials.
  * `verifier_unisa`: University that can verify presentations.
  * `studente_mariorossi`: Student who can manage their wallet and create presentations.
