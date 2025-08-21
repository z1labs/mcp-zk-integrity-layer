import { ethers } from 'ethers';
import { ZK_CONSTANTS } from './constants';

export async function generatePoseidonHash(inputs: string[]): Promise<string> {
    const concatenated = inputs.join('');
    const hash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes('poseidon:' + concatenated));
    
    const fieldSize = BigInt(ZK_CONSTANTS.POSEIDON_CONSTANTS.RATE);
    const hashBigInt = BigInt(hash);
    const moduloHash = hashBigInt % fieldSize;
    
    return '0x' + moduloHash.toString(16).padStart(64, '0');
}

export async function generateKeccakHash(inputs: string[]): Promise<string> {
    const encoded = ethers.utils.defaultAbiCoder.encode(
        inputs.map(() => 'bytes32'),
        inputs
    );
    return ethers.utils.keccak256(encoded);
}

export function createCommitment(hash: string, salt: string): string {
    return ethers.utils.solidityKeccak256(
        ['bytes32', 'bytes32'],
        [hash, salt]
    );
}

export function generateWitness(
    publicInputs: string[],
    privateInputs: string[],
    salt: string
): any {
    const witness = {
        public: publicInputs.map(input => BigInt(input)),
        private: privateInputs.map(input => BigInt(input)),
        salt: BigInt(salt),
        timestamp: BigInt(Date.now())
    };
    
    return witness;
}

export interface MerkleTree {
    root: string;
    leaves: string[];
    layers: string[][];
    getProof(index: number): { pathElements: string[], pathIndices: number[] };
}

export function buildMerkleTree(leaves: string[]): MerkleTree {
    const layers: string[][] = [leaves];
    
    while (layers[layers.length - 1].length > 1) {
        const currentLayer = layers[layers.length - 1];
        const nextLayer: string[] = [];
        
        for (let i = 0; i < currentLayer.length; i += 2) {
            const left = currentLayer[i];
            const right = currentLayer[i + 1] || left;
            const parent = ethers.utils.solidityKeccak256(
                ['bytes32', 'bytes32'],
                [left, right]
            );
            nextLayer.push(parent);
        }
        
        layers.push(nextLayer);
    }
    
    const getProof = (index: number) => {
        const pathElements: string[] = [];
        const pathIndices: number[] = [];
        
        for (let level = 0; level < layers.length - 1; level++) {
            const levelIndex = Math.floor(index / Math.pow(2, level));
            const isLeft = levelIndex % 2 === 0;
            const siblingIndex = isLeft ? levelIndex + 1 : levelIndex - 1;
            
            if (siblingIndex < layers[level].length) {
                pathElements.push(layers[level][siblingIndex]);
                pathIndices.push(isLeft ? 0 : 1);
            }
        }
        
        return { pathElements, pathIndices };
    };
    
    return {
        root: layers[layers.length - 1][0],
        leaves,
        layers,
        getProof
    };
}

export function verifyMerkleProof(
    leaf: string,
    root: string,
    pathElements: string[],
    pathIndices: number[]
): boolean {
    let current = leaf;
    
    for (let i = 0; i < pathElements.length; i++) {
        const sibling = pathElements[i];
        const isLeft = pathIndices[i] === 0;
        
        current = isLeft
            ? ethers.utils.solidityKeccak256(['bytes32', 'bytes32'], [current, sibling])
            : ethers.utils.solidityKeccak256(['bytes32', 'bytes32'], [sibling, current]);
    }
    
    return current === root;
}

export function compressProof(proof: any): string {
    const compressed = {
        a: [proof.pi_a[0].slice(2), proof.pi_a[1].slice(2)],
        b: [
            [proof.pi_b[0][0].slice(2), proof.pi_b[0][1].slice(2)],
            [proof.pi_b[1][0].slice(2), proof.pi_b[1][1].slice(2)]
        ],
        c: [proof.pi_c[0].slice(2), proof.pi_c[1].slice(2)],
        p: proof.protocol
    };
    
    return ethers.utils.hexlify(
        ethers.utils.toUtf8Bytes(JSON.stringify(compressed))
    );
}

export function decompressProof(compressedProof: string): any {
    const decompressed = JSON.parse(
        ethers.utils.toUtf8String(compressedProof)
    );
    
    return {
        pi_a: ['0x' + decompressed.a[0], '0x' + decompressed.a[1]],
        pi_b: [
            ['0x' + decompressed.b[0][0], '0x' + decompressed.b[0][1]],
            ['0x' + decompressed.b[1][0], '0x' + decompressed.b[1][1]]
        ],
        pi_c: ['0x' + decompressed.c[0], '0x' + decompressed.c[1]],
        protocol: decompressed.p
    };
}

export function calculateProofHash(proof: any, publicInputs: string[]): string {
    const encoded = ethers.utils.defaultAbiCoder.encode(
        ['bytes', 'bytes32[]'],
        [JSON.stringify(proof), publicInputs]
    );
    return ethers.utils.keccak256(encoded);
}

export function validateInputs(
    publicInputs: string[],
    privateInputs: string[],
    maxPublicInputs: number,
    maxPrivateInputs: number
): { valid: boolean; error?: string } {
    if (publicInputs.length === 0) {
        return { valid: false, error: 'No public inputs provided' };
    }
    
    if (publicInputs.length > maxPublicInputs) {
        return { valid: false, error: `Too many public inputs (max: ${maxPublicInputs})` };
    }
    
    if (privateInputs.length > maxPrivateInputs) {
        return { valid: false, error: `Too many private inputs (max: ${maxPrivateInputs})` };
    }
    
    for (const input of [...publicInputs, ...privateInputs]) {
        if (!ethers.utils.isHexString(input)) {
            return { valid: false, error: 'Invalid hex string in inputs' };
        }
    }
    
    return { valid: true };
}

export function generateNullifier(
    commitment: string,
    secret: string
): string {
    return ethers.utils.solidityKeccak256(
        ['bytes32', 'bytes32'],
        [commitment, secret]
    );
}

export function createZkIdentity(): {
    trapdoor: string;
    nullifier: string;
    commitment: string;
} {
    const trapdoor = ethers.utils.hexlify(ethers.utils.randomBytes(32));
    const nullifier = ethers.utils.hexlify(ethers.utils.randomBytes(32));
    
    const commitment = ethers.utils.solidityKeccak256(
        ['bytes32', 'bytes32'],
        [trapdoor, nullifier]
    );
    
    return {
        trapdoor,
        nullifier,
        commitment
    };
}

export async function simulateCircuitDelay(circuitType: string): Promise<void> {
    const delays = {
        poseidon: 100,
        keccak: 150,
        hybrid: 250
    };
    
    const delay = delays[circuitType] || 100;
    await new Promise(resolve => setTimeout(resolve, delay));
}

export function formatProofForChain(proof: any, chainName: string): any {
    const formatters = {
        ETHEREUM: (p: any) => ({
            a: [p.pi_a[0], p.pi_a[1]],
            b: [[p.pi_b[0][0], p.pi_b[0][1]], [p.pi_b[1][0], p.pi_b[1][1]]],
            c: [p.pi_c[0], p.pi_c[1]]
        }),
        CYPHER: (p: any) => ({
            proof: compressProof(p)
        }),
        ARBITRUM: (p: any) => ({
            data: ethers.utils.defaultAbiCoder.encode(
                ['uint256[2]', 'uint256[2][2]', 'uint256[2]'],
                [[p.pi_a[0], p.pi_a[1]], [[p.pi_b[0][0], p.pi_b[0][1]], [p.pi_b[1][0], p.pi_b[1][1]]], [p.pi_c[0], p.pi_c[1]]]
            )
        })
    };
    
    const formatter = formatters[chainName];
    return formatter ? formatter(proof) : proof;
}