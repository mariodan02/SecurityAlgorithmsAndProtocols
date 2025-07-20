Dopo aver installato requirements.txt e fatto venv

Generare certificati da src/pki/certificate_authority.py

Per far partire ganache in ascolto sulla porta 8545 lanciare da terminale: ganache -e 2000000000000000 

Prendere
Private Keys (0) - ad esempio: 0xb1c1952037b07a53a9a53b54b84e66d67ec514b8ac8a8469fc7dbb7e04e68d60
E incollarla in blockchain_service.py assegnandola alla variabile GANACHE_BANKER_KEY 

Runnare il progetto con run_system.py
Aprire nel browser il server https://localhost:8443/

Aprire dashboard http://localhost:8000

Fare ciò che si vuole!