const { Web3 } = require('web3');
const fs = require('fs');
const path = require('path');

// Connettiamo a Ganache
const ganacheUrl = 'http://127.0.0.1:7545'; 
const web3 = new Web3(ganacheUrl);

const contractName = 'CredentialRegistry';

// Carica ABI e Bytecode dai file
const abiPath = path.resolve(__dirname, `${contractName}Abi.json`);
const abi = JSON.parse(fs.readFileSync(abiPath, 'utf8'));

const bytecodePath = path.resolve(__dirname, `${contractName}Bytecode.bin`);
const bytecode = fs.readFileSync(bytecodePath, 'utf8');

async function deploy() {
    console.log('deploy del contratto...');

    // Prende la lista degli account da Ganache
    const accounts = await web3.eth.getAccounts();
    const deployerAccount = accounts[0]; // Usiamo il primo account come emittente/deployer
    console.log(`Deploying dall'account: ${deployerAccount}`);

    // Crea un'istanza del contratto
    const contract = new web3.eth.Contract(abi);

    // Esegue il deploy
    const deployedContract = await contract.deploy({
        data: '0x' + bytecode,
    }).send({
        from: deployerAccount,
        gas: '1500000',
    });

    const contractAddress = deployedContract.options.address;
    console.log(` Contratto deployato con successo all'indirizzo: ${contractAddress}`);

    // Salva l'indirizzo del contratto per poterlo usare in altri script
    fs.writeFileSync(path.resolve(__dirname, 'contract-address.txt'), contractAddress);
    console.log('Indirizzo del contratto salvato in: contract-address.txt');
}

deploy().catch(err => {
    console.error('Deployment fallito:', err);
});