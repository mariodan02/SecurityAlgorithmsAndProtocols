const { Web3 } = require('web3');
const fs = require('fs');
const path = require('path');

// Connettiti a Ganache [cite: 966]
const ganacheUrl = 'http://127.0.0.1:7545'; // Assicurati che sia l'URL corretto di Ganache
const web3 = new Web3(ganacheUrl);

const contractName = 'CredentialRegistry';

// Carica ABI e Bytecode dai file
const abiPath = path.resolve(__dirname, `${contractName}Abi.json`);
const abi = JSON.parse(fs.readFileSync(abiPath, 'utf8'));

const bytecodePath = path.resolve(__dirname, `${contractName}Bytecode.bin`);
const bytecode = fs.readFileSync(bytecodePath, 'utf8');

async function deploy() {
    console.log('Attempting to deploy contract...');

    // Prendi la lista degli account da Ganache [cite: 1171, 1174]
    const accounts = await web3.eth.getAccounts();
    const deployerAccount = accounts[0]; // Usiamo il primo account come emittente/deployer
    console.log(`Deploying from account: ${deployerAccount}`);

    // Crea un'istanza del contratto [cite: 1185, 1188]
    const contract = new web3.eth.Contract(abi);

    // Esegui il deploy [cite: 1200, 1205]
    const deployedContract = await contract.deploy({
        data: '0x' + bytecode,
    }).send({
        from: deployerAccount,
        gas: '1500000',
    });

    const contractAddress = deployedContract.options.address;
    console.log(`✅ Contract deployed successfully at address: ${contractAddress}`);

    // Salva l'indirizzo del contratto per poterlo usare in altri script
    fs.writeFileSync(path.resolve(__dirname, 'contract-address.txt'), contractAddress);
    console.log('Contract address saved to contract-address.txt');
}

deploy().catch(err => {
    console.error('Deployment failed:', err);
});