import { IsEnum, IsArray, IsString, IsOptional, IsNumber, ValidateNested, IsBoolean } from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { CircuitType } from '../types';

export class GenerateProofDto {
    @ApiProperty({ enum: CircuitType, description: 'Type of ZK circuit to use' })
    @IsEnum(CircuitType)
    circuitType: CircuitType;

    @ApiProperty({ type: [String], description: 'Public inputs for the proof' })
    @IsArray()
    @IsString({ each: true })
    publicInputs: string[];

    @ApiPropertyOptional({ type: [String], description: 'Private inputs for the proof' })
    @IsOptional()
    @IsArray()
    @IsString({ each: true })
    privateInputs?: string[];

    @ApiPropertyOptional({ description: 'Merkle tree depth' })
    @IsOptional()
    @IsNumber()
    merkleDepth?: number;

    @ApiPropertyOptional({ description: 'Additional metadata' })
    @IsOptional()
    metadata?: Record<string, any>;
}

export class VerifyProofDto {
    @ApiProperty({ description: 'Serialized proof data' })
    @IsString()
    proof: string;

    @ApiProperty({ type: [String], description: 'Public inputs used in proof generation' })
    @IsArray()
    @IsString({ each: true })
    publicInputs: string[];

    @ApiProperty({ description: 'Commitment hash' })
    @IsString()
    commitment: string;

    @ApiProperty({ description: 'Nullifier hash' })
    @IsString()
    nullifier: string;

    @ApiPropertyOptional({ description: 'Chain name for verification' })
    @IsOptional()
    @IsString()
    chainName?: string;
}

export class BatchProofDto {
    @ApiProperty({ type: [GenerateProofDto], description: 'Array of proof generation parameters' })
    @ValidateNested({ each: true })
    @Type(() => GenerateProofDto)
    proofs: GenerateProofDto[];

    @ApiProperty({ 
        enum: ['sequential', 'parallel', 'recursive'],
        description: 'How to aggregate the proofs' 
    })
    @IsString()
    aggregationType: 'sequential' | 'parallel' | 'recursive';

    @ApiPropertyOptional({ description: 'Compression level (0-9)' })
    @IsOptional()
    @IsNumber()
    compressionLevel?: number;
}

export class MerkleProofDto {
    @ApiProperty({ description: 'Leaf value to prove membership for' })
    @IsString()
    leaf: string;

    @ApiProperty({ type: [String], description: 'All leaves in the merkle tree' })
    @IsArray()
    @IsString({ each: true })
    leaves: string[];
}

export class ProofStatusDto {
    @ApiProperty({ description: 'Hash of the proof to check' })
    @IsString()
    proofHash: string;

    @ApiPropertyOptional({ description: 'Chain name to check on' })
    @IsOptional()
    @IsString()
    chainName?: string;
}

export class ProofResponseDto {
    @ApiProperty({ enum: CircuitType })
    type: CircuitType;

    @ApiProperty({ description: 'Serialized proof data' })
    proof: string;

    @ApiProperty({ type: [String] })
    publicInputs: string[];

    @ApiProperty({ description: 'Commitment hash' })
    commitment: string;

    @ApiProperty({ description: 'Nullifier hash' })
    nullifier: string;

    @ApiProperty({ description: 'Merkle root' })
    merkleRoot: string;

    @ApiProperty({ description: 'Proof generation timestamp' })
    timestamp: number;

    @ApiProperty({ description: 'Verification status' })
    verified: boolean;

    @ApiPropertyOptional({ description: 'Transaction hash if stored on-chain' })
    @IsOptional()
    transactionHash?: string;

    @ApiPropertyOptional({ description: 'Transaction link' })
    @IsOptional()
    transactionLink?: string;
}

export class VerificationResultDto {
    @ApiProperty({ description: 'Whether the proof is valid' })
    @IsBoolean()
    valid: boolean;

    @ApiProperty({ description: 'Verification timestamp' })
    @IsNumber()
    timestamp: number;

    @ApiProperty({ description: 'Verifier contract address' })
    @IsString()
    verifier: string;

    @ApiProperty({ description: 'Hash of the verified proof' })
    @IsString()
    proofHash: string;

    @ApiPropertyOptional({ description: 'Error message if verification failed' })
    @IsOptional()
    @IsString()
    error?: string;
}

export class IntegrityCheckpointDto {
    @ApiProperty({ description: 'Starting block number' })
    @IsNumber()
    startBlock: number;

    @ApiProperty({ description: 'Ending block number' })
    @IsNumber()
    endBlock: number;

    @ApiPropertyOptional({ description: 'Include detailed validation results' })
    @IsOptional()
    @IsBoolean()
    includeDetails?: boolean;
}