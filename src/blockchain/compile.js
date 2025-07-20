const path = require('path');
const fs = require('fs');
const solc = require('solc');

const contractName = 'CredentialRegistry';
const fileName = `${contractName}.sol`;

// 1. PERCORSO DEL FILE SOLIDITY 
const contractPath = path.resolve(__dirname, fileName);
const sourceCode = fs.readFileSync(contractPath, 'utf8');

const input = {
    language: 'Solidity',
    sources: {
        [fileName]: {
            content: sourceCode,
        },
    },
    settings: {
        outputSelection: {
            '*': {
                '*': ['abi', 'evm.bytecode.object'],
            },
        },
    },
};

console.log('Compiling contract...');
const compiledCode = JSON.parse(solc.compile(JSON.stringify(input)));
if (compiledCode.errors) {
    compiledCode.errors.forEach(err => console.error(err.formattedMessage));
    throw new Error("Compilation failed!");
}
console.log('Contract compiled successfully!');

// 2. PERCORSO DEL CONTRATTO COMPILATO 
const compiledContractPath = Object.keys(compiledCode.contracts)[0];
const contract = compiledCode.contracts[compiledContractPath][contractName];
const abi = contract.abi;
const bytecode = contract.evm.bytecode.object;

// Salva l'ABI
const abiPath = path.resolve(__dirname, `${contractName}Abi.json`);
fs.writeFileSync(abiPath, JSON.stringify(abi, null, 2));
console.log(`ABI saved to ${abiPath}`);

// Salva il Bytecode
const bytecodePath = path.resolve(__dirname, `${contractName}Bytecode.bin`);
fs.writeFileSync(bytecodePath, bytecode);
console.log(`Bytecode saved to ${bytecodePath}`);