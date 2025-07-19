const path = require('path');
const fs = require('fs');
const solc = require('solc');

const contractName = 'CredentialRegistry';
const fileName = `${contractName}.sol`;

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
// Compila il contratto
const compiledCode = JSON.parse(solc.compile(JSON.stringify(input)));
console.log('Contract compiled successfully!');

// Estrai ABI e Bytecode
const contract = compiledCode.contracts[fileName][contractName];
const abi = contract.abi;
const bytecode = contract.evm.bytecode.object;

// Salva l'ABI in un file JSON
const abiPath = path.resolve(__dirname, `${contractName}Abi.json`);
fs.writeFileSync(abiPath, JSON.stringify(abi, null, 2));
console.log(`ABI saved to ${abiPath}`);

// Salva il Bytecode in un file .bin
const bytecodePath = path.resolve(__dirname, `${contractName}Bytecode.bin`);
fs.writeFileSync(bytecodePath, bytecode);
console.log(`Bytecode saved to ${bytecodePath}`);