import { ChainNames } from 'modules/blockchain/constants';
import { CircuitType } from './types';

export const ZK_CONSTANTS = {
    CIRCUITS: {
        [CircuitType.POSEIDON]: {
            depth: 20,
            constraints: 50000,
            publicInputCount: 8,
            privateInputCount: 4,
            hashRounds: 8,
            fieldSize: '21888242871839275222246405745257275088548364400416034343698204186575808495617'
        },
        [CircuitType.KECCAK]: {
            depth: 16,
            constraints: 75000,
            publicInputCount: 6,
            privateInputCount: 3,
            blockSize: 1088,
            outputLength: 256
        },
        [CircuitType.HYBRID]: {
            depth: 24,
            constraints: 100000,
            publicInputCount: 10,
            privateInputCount: 5,
            poseidonRatio: 0.6,
            keccakRatio: 0.4
        }
    },

    VERIFIER_CONTRACTS: {
        [ChainNames.CYPHER]: {
            [CircuitType.POSEIDON]: '0x1234567890123456789012345678901234567890',
            [CircuitType.KECCAK]: '0x2345678901234567890123456789012345678901',
            [CircuitType.HYBRID]: '0x3456789012345678901234567890123456789012'
        },
        [ChainNames.ETHEREUM]: {
            [CircuitType.POSEIDON]: '0x4567890123456789012345678901234567890123',
            [CircuitType.KECCAK]: '0x5678901234567890123456789012345678901234',
            [CircuitType.HYBRID]: '0x6789012345678901234567890123456789012345'
        },
        [ChainNames.ARBITRUM]: {
            [CircuitType.POSEIDON]: '0x7890123456789012345678901234567890123456',
            [CircuitType.KECCAK]: '0x8901234567890123456789012345678901234567',
            [CircuitType.HYBRID]: '0x9012345678901234567890123456789012345678'
        }
    },

    STORAGE_CONTRACT: '0xabc1234567890123456789012345678901234567',

    PROOF_EXPIRY_TIME: 86400000,

    MAX_BATCH_SIZE: 100,

    MERKLE_TREE_HEIGHT: 32,

    GAS_LIMITS: {
        GENERATE_PROOF: 500000,
        VERIFY_PROOF: 300000,
        STORE_PROOF: 200000,
        BATCH_VERIFY: 1000000
    },

    CIRCUIT_CONSTRAINTS: {
        MAX_PUBLIC_INPUTS: 16,
        MAX_PRIVATE_INPUTS: 8,
        MAX_WITNESS_SIZE: 1024 * 1024,
        MAX_PROOF_SIZE: 2048
    },

    POSEIDON_CONSTANTS: {
        T: 6,
        RF: 8,
        RP: 57,
        RATE: 5,
        CAPACITY: 1
    },

    KECCAK_CONSTANTS: {
        RATE: 1088,
        CAPACITY: 512,
        DELIMITED_SUFFIX: 0x06,
        HASH_BIT_LENGTH: 256
    },

    VERIFIER_ABI: [
        {
            "inputs": [
                {
                    "internalType": "bytes",
                    "name": "proof",
                    "type": "bytes"
                },
                {
                    "internalType": "uint256[]",
                    "name": "publicInputs",
                    "type": "uint256[]"
                },
                {
                    "internalType": "bytes32",
                    "name": "commitment",
                    "type": "bytes32"
                }
            ],
            "name": "verifyProof",
            "outputs": [
                {
                    "internalType": "bool",
                    "name": "",
                    "type": "bool"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        }
    ],

    STORAGE_ABI: [
        {
            "inputs": [
                {
                    "internalType": "address",
                    "name": "user",
                    "type": "address"
                },
                {
                    "internalType": "bytes32",
                    "name": "commitment",
                    "type": "bytes32"
                },
                {
                    "internalType": "bytes32",
                    "name": "nullifier",
                    "type": "bytes32"
                },
                {
                    "internalType": "bytes32",
                    "name": "merkleRoot",
                    "type": "bytes32"
                },
                {
                    "internalType": "bytes",
                    "name": "proof",
                    "type": "bytes"
                }
            ],
            "name": "storeProof",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "bytes32",
                    "name": "proofHash",
                    "type": "bytes32"
                }
            ],
            "name": "getProofStatus",
            "outputs": [
                {
                    "components": [
                        {
                            "internalType": "bool",
                            "name": "exists",
                            "type": "bool"
                        },
                        {
                            "internalType": "bool",
                            "name": "verified",
                            "type": "bool"
                        },
                        {
                            "internalType": "uint256",
                            "name": "timestamp",
                            "type": "uint256"
                        },
                        {
                            "internalType": "bool",
                            "name": "nullifierUsed",
                            "type": "bool"
                        }
                    ],
                    "internalType": "struct ProofStatus",
                    "name": "",
                    "type": "tuple"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        }
    ],

    ERROR_MESSAGES: {
        CIRCUIT_NOT_INITIALIZED: 'Circuit not initialized',
        INVALID_PROOF: 'Invalid proof format',
        PROOF_EXPIRED: 'Proof has expired',
        NULLIFIER_ALREADY_USED: 'Nullifier has already been used',
        INSUFFICIENT_PUBLIC_INPUTS: 'Insufficient public inputs',
        MERKLE_PROOF_INVALID: 'Invalid merkle proof',
        WITNESS_GENERATION_FAILED: 'Failed to generate witness',
        COMMITMENT_MISMATCH: 'Commitment does not match inputs'
    }
} as const;