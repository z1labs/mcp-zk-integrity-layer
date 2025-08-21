export enum CircuitType {
    POSEIDON = 'poseidon',
    KECCAK = 'keccak',
    HYBRID = 'hybrid'
}

export interface ZkProof {
    type: CircuitType;
    proof: string;
    publicInputs: string[];
    commitment: string;
    nullifier: string;
    merkleRoot: string;
    timestamp: number;
    verified: boolean;
}

export interface ProofGenerationParams {
    circuitType: CircuitType;
    publicInputs: string[];
    privateInputs?: string[];
    merkleDepth?: number;
    metadata?: Record<string, any>;
}

export interface VerificationResult {
    valid: boolean;
    timestamp: number;
    verifier: string;
    proofHash: string;
    error?: string;
}

export interface MerkleProof {
    leaf: string;
    root: string;
    pathElements: string[];
    pathIndices: number[];
}

export interface CommitmentData {
    commitment: string;
    nullifier: string;
    root: string;
}

export interface WitnessData {
    publicSignals: string[];
    privateSignals: string[];
    salt: string;
    timestamp: number;
}

export interface CircuitConfig {
    depth: number;
    constraints: number;
    publicInputCount: number;
    privateInputCount: number;
}

export interface ProofMetadata {
    userId: string;
    walletAddress: string;
    chainId: number;
    blockNumber: number;
    transactionHash?: string;
}

export interface ZkIntegrityCheckpoint {
    id: string;
    proofHash: string;
    merkleRoot: string;
    timestamp: number;
    blockHeight: number;
    verified: boolean;
}

export interface BatchProofRequest {
    proofs: ProofGenerationParams[];
    aggregationType: 'sequential' | 'parallel' | 'recursive';
    compressionLevel?: number;
}

export interface ProofValidationRules {
    maxAge?: number;
    requiredCircuitType?: CircuitType;
    minPublicInputs?: number;
    allowNullifierReuse?: boolean;
}

export interface ZkCircuitStats {
    circuitType: CircuitType;
    totalProofs: number;
    validProofs: number;
    averageProofTime: number;
    lastProofTimestamp: number;
}

export interface IntegrityReport {
    checkpointId: string;
    startBlock: number;
    endBlock: number;
    proofCount: number;
    validationResults: VerificationResult[];
    merkleRoot: string;
    signature: string;
}