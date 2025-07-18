Infrastruttura a Chiave Pubblica (PKI) per Credenziali Accademiche

Questo documento descrive la procedura completa per creare e gestire una Certificate Authority (CA) a due livelli (Root e Intermedia) utilizzando OpenSSL. L'intera struttura verrà creata localmente, garantendo la piena portabilità del progetto.

Prerequisiti

    openssl installato nel sistema.

Parte 1: Creazione della Root CA

La Root CA è il vertice della nostra catena di fiducia. La sua chiave privata va protetta con la massima cura e usata solo per firmare i certificati delle CA Intermedie.

1. Setup dell'Ambiente

Esegui questo blocco per creare la struttura di directory e i file di configurazione necessari. Tutti i percorsi sono relativi alla directory corrente.
Bash

# Creare la struttura di directory principale
mkdir -p ./root/ca/{certs,crl,newcerts,private}
chmod 700 ./root/ca/private

# Creare il database dei certificati e il file per il numero seriale
touch ./root/ca/index.txt
echo 1000 > ./root/ca/serial

# Creare il file di configurazione CORRETTO per la Root CA
tee ./root/ca/openssl.cnf > /dev/null <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ./root/ca
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand

private_key       = \$dir/private/ca.key.pem
certificate       = \$dir/certs/ca.cert.pem

crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = IT
stateOrProvinceName             = State or Province Name
stateOrProvinceName_default     = Salerno
localityName                    = Locality Name
0.organizationName              = Organization Name
0.organizationName_default      = Universita degli Studi di Salerno
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

# Sezione per firmare la CA Intermedia
[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
authorityInfoAccess = OCSP;URI:http://ocsp.unisa.it

[ crl_ext ]
authorityKeyIdentifier=keyid:always
EOF

2. Creazione della Chiave Privata e del Certificato della Root CA

Bash

# Generare la chiave privata della Root CA
openssl genrsa -aes256 -out ./root/ca/private/ca.key.pem 4096
chmod 400 ./root/ca/private/ca.key.pem

# Creare il certificato auto-firmato della Root CA (validità 20 anni)
openssl req -config ./root/ca/openssl.cnf \
      -key ./root/ca/private/ca.key.pem \
      -new -x509 -days 7300 -sha256 -extensions v3_ca \
      -out ./root/ca/certs/ca.cert.pem
chmod 444 ./root/ca/certs/ca.cert.pem

Verrà richiesta una password per la chiave e le informazioni per il certificato. Puoi premere Invio per accettare i default (IT, Salerno, Universita degli Studi di Salerno) e inserire manualmente solo i campi senza default come il Common Name (es. "UNISA Academic Credentials - Root CA").

Parte 2: Creazione della Intermediate CA

La CA Intermedia verrà usata per le operazioni quotidiane di firma.

1. Setup dell'Ambiente Intermedio

Bash

# Creare le directory per la CA intermedia
mkdir -p ./root/ca/intermediate/{certs,crl,csr,newcerts,private}
chmod 700 ./root/ca/intermediate/private

# Creare i file di database per la CA intermedia
touch ./root/ca/intermediate/index.txt
echo 1000 > ./root/ca/intermediate/serial
echo 1000 > ./root/ca/intermediate/crlnumber

# Creare il file di configurazione per la CA Intermedia
tee ./root/ca/intermediate/openssl.cnf > /dev/null <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ./root/ca/intermediate
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand
private_key       = \$dir/private/intermediate.key.pem
certificate       = \$dir/certs/intermediate.cert.pem
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/intermediate.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = IT
stateOrProvinceName             = State or Province Name
stateOrProvinceName_default     = Salerno
localityName                    = Locality Name
0.organizationName              = Organization Name
0.organizationName_default      = Universita degli Studi di Salerno
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
authorityInfoAccess = OCSP;URI:http://ocsp.unisa.it

[ crl_ext ]
authorityKeyIdentifier=keyid:always
EOF

2. Creazione della Chiave, CSR, e Certificato Intermedio

Bash

# Generare la chiave privata della CA intermedia
openssl genrsa -aes256 \
  -out ./root/ca/intermediate/private/intermediate.key.pem 4096
chmod 400 ./root/ca/intermediate/private/intermediate.key.pem

# Creare la CSR per la CA intermedia
openssl req -config ./root/ca/intermediate/openssl.cnf -new -sha256 \
      -key ./root/ca/intermediate/private/intermediate.key.pem \
      -out ./root/ca/intermediate/csr/intermediate.csr.pem

# Firmare la CSR con la Root CA (validità 10 anni)
openssl ca -config ./root/ca/openssl.cnf -extensions v3_intermediate_ca \
      -days 3650 -notext -md sha256 \
      -in ./root/ca/intermediate/csr/intermediate.csr.pem \
      -out ./root/ca/intermediate/certs/intermediate.cert.pem
chmod 444 ./root/ca/intermediate/certs/intermediate.cert.pem

Per la CSR, potrai accettare i valori di default e inserire solo il Common Name (es. "UNISA Academic Credentials - Intermediate CA"). Per la firma, ti verrà chiesta la password della chiave della Root CA.

3. Verifica e Creazione della Catena di Certificati

Bash

# Verificare che il certificato intermedio sia correttamente firmato
openssl verify -CAfile /home/mario/Documenti/GitHub/SecurityAlgorithmsAndProtocols/root/ca/certs/ca.cert.pem \
      /home/mario/Documenti/GitHub/SecurityAlgorithmsAndProtocols/root/ca/certs/ca.cert.pem
# Risultato atteso: /home/mario/Documenti/GitHub/SecurityAlgorithmsAndProtocols/root/ca/certs/ca.cert.pem: OK

# Creare il file della catena di certificati per i client
sudo sh -c 'cat ./root/ca/intermediate/certs/intermediate.cert.pem ./root/ca/certs/ca.cert.pem > ./root/ca/intermediate/certs/ca-chain.cert.pem'
chmod 444 ./root/ca/intermediate/certs/ca-chain.cert.pem

Parte 3: Gestione della CA

Firma di un Certificato per un'Entità Finale (es. Università)

    L'entità finale (es. Università di Rennes) crea la sua chiave e CSR:
    Bash

# Questo comando verrebbe eseguito dall'università
openssl genrsa -out rennes.key.pem 2048
openssl req -new -sha256 -key rennes.key.pem -out rennes.csr.pem

La CA Intermedia firma la CSR ricevuta:
Bash

    # (Supponendo che rennes.csr.pem sia stato copiato in ./root/ca/intermediate/csr/)
    openssl ca -config ./root/ca/intermediate/openssl.cnf \
        -extensions server_cert -days 375 -notext -md sha256 \
        -in ./root/ca/intermediate/csr/rennes.csr.pem \
        -out ./root/ca/intermediate/certs/rennes.cert.pem

Gestione della Revoca (OCSP)

Il nostro sistema è progettato per usare OCSP per la verifica della revoca in tempo reale, un metodo più efficiente delle CRL. La logica di interrogazione OCSP è implementata in Python nel credentials/validator.py.

Tuttavia, la CA deve comunque sapere quali certificati sono stati revocati.

    Revocare un Certificato:
    Se la chiave di un certificato viene compromessa, la CA Intermedia deve revocarlo.
    Bash

# Revoca il certificato
openssl ca -config ./root/ca/intermediate/openssl.cnf \
      -revoke ./root/ca/intermediate/certs/rennes.cert.pem

Questo comando aggiorna il database index.txt della CA Intermedia, marcando il certificato come revocato (R). Sarà compito del responder OCSP della CA leggere questo stato e rispondere correttamente alle richieste di verifica.

Generare la CRL (Certificate Revocation List):
Anche se usiamo OCSP, è buona norma mantenere una CRL aggiornata come fallback.
Bash

# Genera una nuova CRL
openssl ca -config ./root/ca/intermediate/openssl.cnf \
      -gencrl -out ./root/ca/intermediate/crl/intermediate.crl.pem