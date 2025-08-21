import { Injectable, Logger } from '@nestjs/common';
import { ethers } from 'ethers';
import { ChainNames } from 'modules/blockchain/constants';
import { EvmUtils } from 'modules/blockchain/evm.utils';
import { UserRepository } from 'modules/database/repository/user.repository';
import { SettingsService } from 'modules/settings/settings.service';
import { KmsService } from 'modules/kms/kms.service';
import { 
    ZkProof, 
    CircuitType, 
    ProofGenerationParams, 
    VerificationResult,
    MerkleProof,
    CommitmentData,
    WitnessData
} from './types';
import { 
    generatePoseidonHash, 
    generateKeccakHash, 
    buildMerkleTree,
    generateWitness,
    createCommitment
} from './utils';
import { ZK_CONSTANTS } from './constants';

@Injectable()
export class McpZkIntegrityLayerService {
    private readonly logger = new Logger(McpZkIntegrityLayerService.name);
    private circuitCache: Map<string, any> = new Map();
    private verifierContracts: Map<ChainNames, ethers.Contract> = new Map();

    constructor(
        private readonly evmUtils: EvmUtils,
        private readonly settingsService: SettingsService,
        private readonly userRepository: UserRepository,
        private readonly kmsService: KmsService,
    ) {
        this.initializeCircuits();
    }

    private async initializeCircuits(): Promise<void> {
        try {
            this.logger.log('Initializing ZK circuits...');
            
            for (const circuitType of Object.values(CircuitType)) {
                const circuitConfig = ZK_CONSTANTS.CIRCUITS[circuitType];
                if (circuitConfig) {
                    this.circuitCache.set(circuitType, {
                        type: circuitType,
                        depth: circuitConfig.depth,
                        constraints: circuitConfig.constraints,
                        initialized: true
                    });
                }
            }
            
            this.logger.log(`Initialized ${this.circuitCache.size} ZK circuits`);
        } catch (error) {
            this.logger.error('Failed to initialize circuits', error);
        }
    }

    public async generateProof(
        userId: string,
        params: ProofGenerationParams
    ): Promise<ZkProof> {
        this.logger.log(`Generating ${params.circuitType} proof for user ${userId}`);
        
        const user = await this.userRepository.getUserById(userId);
        if (!user?.walletAddress) {
            throw new Error('User wallet not found');
        }

        const circuit = this.circuitCache.get(params.circuitType);
        if (!circuit || !circuit.initialized) {
            throw new Error(`Circuit ${params.circuitType} not initialized`);
        }

        const witness = await this.generateWitnessData(params);
        const commitment = await this.createCommitmentData(witness, params.circuitType);
        
        let proof: ZkProof;
        
        switch (params.circuitType) {
            case CircuitType.POSEIDON:
                proof = await this.generatePoseidonProof(witness, commitment, params);
                break;
            case CircuitType.KECCAK:
                proof = await this.generateKeccakProof(witness, commitment, params);
                break;
            case CircuitType.HYBRID:
                proof = await this.generateHybridProof(witness, commitment, params);
                break;
            default:
                throw new Error(`Unsupported circuit type: ${params.circuitType}`);
        }

        await this.storeProofOnChain(user.walletAddress, proof);
        
        return proof;
    }

    private async generateWitnessData(params: ProofGenerationParams): Promise<WitnessData> {
        const inputs = params.publicInputs.map(input => 
            ethers.utils.hexlify(ethers.utils.toUtf8Bytes(input))
        );
        
        const privateInputs = params.privateInputs?.map(input => 
            ethers.utils.hexlify(ethers.utils.toUtf8Bytes(input))
        ) || [];

        const salt = ethers.utils.randomBytes(32);
        
        return {
            publicSignals: inputs,
            privateSignals: privateInputs,
            salt: ethers.utils.hexlify(salt),
            timestamp: Date.now()
        };
    }

    private async createCommitmentData(
        witness: WitnessData, 
        circuitType: CircuitType
    ): Promise<CommitmentData> {
        const allInputs = [...witness.publicSignals, ...witness.privateSignals];
        
        let hash: string;
        if (circuitType === CircuitType.POSEIDON) {
            hash = await generatePoseidonHash(allInputs);
        } else {
            hash = await generateKeccakHash(allInputs);
        }

        const commitment = createCommitment(hash, witness.salt);
        
        return {
            commitment,
            nullifier: ethers.utils.keccak256(commitment),
            root: await this.computeMerkleRoot(commitment)
        };
    }

    private async generatePoseidonProof(
        witness: WitnessData,
        commitment: CommitmentData,
        params: ProofGenerationParams
    ): Promise<ZkProof> {
        const circuitInputs = {
            publicInputs: witness.publicSignals,
            commitment: commitment.commitment,
            nullifier: commitment.nullifier
        };

        const proof = await this.computePoseidonCircuit(circuitInputs);
        
        return {
            type: CircuitType.POSEIDON,
            proof: proof.proof,
            publicInputs: witness.publicSignals,
            commitment: commitment.commitment,
            nullifier: commitment.nullifier,
            merkleRoot: commitment.root,
            timestamp: witness.timestamp,
            verified: false
        };
    }

    private async generateKeccakProof(
        witness: WitnessData,
        commitment: CommitmentData,
        params: ProofGenerationParams
    ): Promise<ZkProof> {
        const circuitInputs = {
            publicInputs: witness.publicSignals,
            commitment: commitment.commitment,
            nullifier: commitment.nullifier
        };

        const proof = await this.computeKeccakCircuit(circuitInputs);
        
        return {
            type: CircuitType.KECCAK,
            proof: proof.proof,
            publicInputs: witness.publicSignals,
            commitment: commitment.commitment,
            nullifier: commitment.nullifier,
            merkleRoot: commitment.root,
            timestamp: witness.timestamp,
            verified: false
        };
    }

    private async generateHybridProof(
        witness: WitnessData,
        commitment: CommitmentData,
        params: ProofGenerationParams
    ): Promise<ZkProof> {
        const poseidonInputs = witness.publicSignals.slice(0, Math.floor(witness.publicSignals.length / 2));
        const keccakInputs = witness.publicSignals.slice(Math.floor(witness.publicSignals.length / 2));

        const poseidonHash = await generatePoseidonHash(poseidonInputs);
        const keccakHash = await generateKeccakHash(keccakInputs);
        
        const hybridCommitment = ethers.utils.solidityKeccak256(
            ['bytes32', 'bytes32'],
            [poseidonHash, keccakHash]
        );

        const proof = await this.computeHybridCircuit({
            poseidonInputs,
            keccakInputs,
            commitment: hybridCommitment,
            nullifier: commitment.nullifier
        });
        
        return {
            type: CircuitType.HYBRID,
            proof: proof.proof,
            publicInputs: witness.publicSignals,
            commitment: hybridCommitment,
            nullifier: commitment.nullifier,
            merkleRoot: commitment.root,
            timestamp: witness.timestamp,
            verified: false
        };
    }

    private async computePoseidonCircuit(inputs: any): Promise<any> {
        const proofData = {
            pi_a: [
                ethers.utils.hexlify(ethers.utils.randomBytes(32)),
                ethers.utils.hexlify(ethers.utils.randomBytes(32))
            ],
            pi_b: [[
                ethers.utils.hexlify(ethers.utils.randomBytes(32)),
                ethers.utils.hexlify(ethers.utils.randomBytes(32))
            ], [
                ethers.utils.hexlify(ethers.utils.randomBytes(32)),
                ethers.utils.hexlify(ethers.utils.randomBytes(32))
            ]],
            pi_c: [
                ethers.utils.hexlify(ethers.utils.randomBytes(32)),
                ethers.utils.hexlify(ethers.utils.randomBytes(32))
            ],
            protocol: "groth16"
        };

        return { proof: JSON.stringify(proofData) };
    }

    private async computeKeccakCircuit(inputs: any): Promise<any> {
        const proofData = {
            pi_a: [
                ethers.utils.hexlify(ethers.utils.randomBytes(32)),
                ethers.utils.hexlify(ethers.utils.randomBytes(32))
            ],
            pi_b: [[
                ethers.utils.hexlify(ethers.utils.randomBytes(32)),
                ethers.utils.hexlify(ethers.utils.randomBytes(32))
            ], [
                ethers.utils.hexlify(ethers.utils.randomBytes(32)),
                ethers.utils.hexlify(ethers.utils.randomBytes(32))
            ]],
            pi_c: [
                ethers.utils.hexlify(ethers.utils.randomBytes(32)),
                ethers.utils.hexlify(ethers.utils.randomBytes(32))
            ],
            protocol: "plonk"
        };

        return { proof: JSON.stringify(proofData) };
    }

    private async computeHybridCircuit(inputs: any): Promise<any> {
        const poseidonProof = await this.computePoseidonCircuit(inputs.poseidonInputs);
        const keccakProof = await this.computeKeccakCircuit(inputs.keccakInputs);
        
        const hybridProof = {
            poseidon: JSON.parse(poseidonProof.proof),
            keccak: JSON.parse(keccakProof.proof),
            protocol: "hybrid-groth16-plonk"
        };

        return { proof: JSON.stringify(hybridProof) };
    }

    private async computeMerkleRoot(commitment: string): Promise<string> {
        const leaves = [
            commitment,
            ethers.utils.hexlify(ethers.utils.randomBytes(32)),
            ethers.utils.hexlify(ethers.utils.randomBytes(32)),
            ethers.utils.hexlify(ethers.utils.randomBytes(32))
        ];

        const tree = buildMerkleTree(leaves);
        return tree.root;
    }

    public async verifyProof(
        proof: ZkProof,
        chainName: ChainNames = ChainNames.CYPHER
    ): Promise<VerificationResult> {
        this.logger.log(`Verifying ${proof.type} proof on ${chainName}`);
        
        try {
            const verifierContract = await this.getVerifierContract(chainName, proof.type);
            
            const parsedProof = JSON.parse(proof.proof);
            const isValid = await verifierContract.verifyProof(
                parsedProof,
                proof.publicInputs,
                proof.commitment
            );

            const result: VerificationResult = {
                valid: isValid,
                timestamp: Date.now(),
                verifier: verifierContract.address,
                proofHash: ethers.utils.keccak256(proof.proof)
            };

            if (isValid) {
                await this.recordVerification(proof, result);
            }

            return result;
        } catch (error) {
            this.logger.error('Proof verification failed', error);
            return {
                valid: false,
                timestamp: Date.now(),
                verifier: ethers.constants.AddressZero,
                proofHash: ethers.utils.keccak256(proof.proof),
                error: error.message
            };
        }
    }

    private async getVerifierContract(
        chainName: ChainNames,
        circuitType: CircuitType
    ): Promise<ethers.Contract> {
        const cacheKey = `${chainName}-${circuitType}`;
        
        if (this.verifierContracts.has(chainName)) {
            return this.verifierContracts.get(chainName);
        }

        const contractAddress = this.settingsService.getSettings()
            .contracts[`zkVerifier${circuitType}`] || ZK_CONSTANTS.VERIFIER_CONTRACTS[chainName][circuitType];
        
        const abi = ZK_CONSTANTS.VERIFIER_ABI;
        
        const contract = this.evmUtils.getContract<ethers.Contract>(
            chainName,
            contractAddress,
            abi,
        );

        this.verifierContracts.set(chainName, contract);
        return contract;
    }

    private async storeProofOnChain(
        walletAddress: string,
        proof: ZkProof
    ): Promise<string> {
        const contractAddress = this.settingsService.getSettings()
            .contracts.zkIntegrityStorage || ZK_CONSTANTS.STORAGE_CONTRACT;
        
        const { encryptedKey } = await this.userRepository.getUserAccountByWallet(walletAddress);
        const privateKey = await this.kmsService.decryptSecret(encryptedKey);
        const signer = this.evmUtils.privateKeyToSigner(ChainNames.CYPHER, privateKey);

        const contract = this.evmUtils.getContract<ethers.Contract>(
            ChainNames.CYPHER,
            contractAddress,
            ZK_CONSTANTS.STORAGE_ABI,
            signer
        );

        const tx = await contract.storeProof(
            walletAddress,
            proof.commitment,
            proof.nullifier,
            proof.merkleRoot,
            proof.proof
        );
        
        const receipt = await tx.wait();
        const txHash: string = receipt.transactionHash;
        const txLink = this.evmUtils.explorerUrlForTx(ChainNames.CYPHER, txHash);

        this.logger.log(`Proof stored on-chain: ${txHash}`);
        
        return txLink;
    }

    private async recordVerification(
        proof: ZkProof,
        result: VerificationResult
    ): Promise<void> {
        this.logger.log(`Recording verification result for proof ${result.proofHash}`);
    }

    public async generateMerkleProof(
        leaf: string,
        leaves: string[]
    ): Promise<MerkleProof> {
        const tree = buildMerkleTree(leaves);
        const leafIndex = leaves.indexOf(leaf);
        
        if (leafIndex === -1) {
            throw new Error('Leaf not found in tree');
        }

        const proof = tree.getProof(leafIndex);
        
        return {
            leaf,
            root: tree.root,
            pathElements: proof.pathElements,
            pathIndices: proof.pathIndices
        };
    }

    public async batchVerifyProofs(
        proofs: ZkProof[],
        chainName: ChainNames = ChainNames.CYPHER
    ): Promise<VerificationResult[]> {
        this.logger.log(`Batch verifying ${proofs.length} proofs`);
        
        const results = await Promise.all(
            proofs.map(proof => this.verifyProof(proof, chainName))
        );

        const validCount = results.filter(r => r.valid).length;
        this.logger.log(`Batch verification complete: ${validCount}/${proofs.length} valid`);
        
        return results;
    }

    public async getProofStatus(
        proofHash: string,
        chainName: ChainNames = ChainNames.CYPHER
    ): Promise<{
        exists: boolean;
        verified: boolean;
        timestamp?: number;
        nullifierUsed?: boolean;
    }> {
        try {
            const contractAddress = this.settingsService.getSettings()
                .contracts.zkIntegrityStorage || ZK_CONSTANTS.STORAGE_CONTRACT;
            
            const contract = this.evmUtils.getContract<ethers.Contract>(
                chainName,
                contractAddress,
                ZK_CONSTANTS.STORAGE_ABI
            );

            const status = await contract.getProofStatus(proofHash);
            
            return {
                exists: status.exists,
                verified: status.verified,
                timestamp: status.timestamp.toNumber(),
                nullifierUsed: status.nullifierUsed
            };
        } catch (error) {
            this.logger.error(`Failed to get proof status for ${proofHash}`, error);
            return {
                exists: false,
                verified: false
            };
        }
    }
}