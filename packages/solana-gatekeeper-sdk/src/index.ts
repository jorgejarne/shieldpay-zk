import { sha256 } from "@noble/hashes/sha2";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import type { VerificationStatus } from "@shieldpay/shared-types";

export const SHIELDPAY_GATEKEEPER_PROGRAM_ID = new PublicKey(
  "51tDw2neaMF7JaZboe58X39sMVQ5E5iJWUSRpLLyxjw7",
);

const CONFIG_SEED = "config";
const REQUEST_SEED = "request";
const STATUS_TO_ANCHOR: Record<VerificationStatus, number> = {
  PENDING: 0,
  APPROVED: 1,
  REJECTED: 2,
  EXPIRED: 3,
};
const ANCHOR_TO_STATUS: Record<number, VerificationStatus> = {
  0: "PENDING",
  1: "APPROVED",
  2: "REJECTED",
  3: "EXPIRED",
};

export interface DecodedRequestAccount {
  merchant: PublicKey;
  requestIdSeed: Uint8Array;
  challengeHash: Uint8Array;
  status: VerificationStatus;
  createdAtUnix: bigint;
  expiresAtUnix: bigint;
  attestationDigest: Uint8Array;
  verifierKeyIdHash: Uint8Array;
  bump: number;
}

export function getRpcUrl(cluster: "localnet" | "devnet"): string {
  if (cluster === "localnet") {
    return "http://127.0.0.1:8899";
  }
  return "https://api.devnet.solana.com";
}

export function deriveConfigPda(programId: PublicKey = SHIELDPAY_GATEKEEPER_PROGRAM_ID): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync([Buffer.from(CONFIG_SEED)], programId);
  return pda;
}

export function deriveRequestPda(
  merchant: PublicKey,
  requestIdSeed16: Uint8Array,
  programId: PublicKey = SHIELDPAY_GATEKEEPER_PROGRAM_ID,
): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from(REQUEST_SEED), merchant.toBuffer(), Buffer.from(requestIdSeed16)],
    programId,
  );
  return pda;
}

export function requestIdSeed16FromString(requestId: string): Uint8Array {
  return sha256(new TextEncoder().encode(requestId)).slice(0, 16);
}

export function challengeHashFromRaw(challenge: string): Uint8Array {
  return sha256(new TextEncoder().encode(challenge));
}

export function verifierKeyIdHashFromString(verifierKeyId: string): Uint8Array {
  return sha256(new TextEncoder().encode(verifierKeyId));
}

export function buildCreateRequestInstruction(params: {
  payer: PublicKey;
  merchant: PublicKey;
  requestPda: PublicKey;
  requestIdSeed16: Uint8Array;
  challengeHash32: Uint8Array;
  expiresAtUnix: bigint;
  programId?: PublicKey;
}): TransactionInstruction {
  const programId = params.programId ?? SHIELDPAY_GATEKEEPER_PROGRAM_ID;
  const data = Buffer.concat([
    instructionDiscriminator("create_request"),
    Buffer.from(params.requestIdSeed16),
    Buffer.from(params.challengeHash32),
    i64Le(params.expiresAtUnix),
  ]);

  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: params.payer, isSigner: true, isWritable: true },
      { pubkey: params.merchant, isSigner: true, isWritable: false },
      { pubkey: params.requestPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

export function buildInitializeConfigInstruction(params: {
  payer: PublicKey;
  configPda: PublicKey;
  authority: PublicKey;
  activeVerifier: PublicKey;
  programId?: PublicKey;
}): TransactionInstruction {
  const programId = params.programId ?? SHIELDPAY_GATEKEEPER_PROGRAM_ID;
  const data = Buffer.concat([
    instructionDiscriminator("initialize_config"),
    params.authority.toBuffer(),
    params.activeVerifier.toBuffer(),
  ]);

  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: params.payer, isSigner: true, isWritable: true },
      { pubkey: params.configPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

export function buildUpdateVerifierKeyInstruction(params: {
  configPda: PublicKey;
  authority: PublicKey;
  nextActiveVerifier: PublicKey;
  programId?: PublicKey;
}): TransactionInstruction {
  const programId = params.programId ?? SHIELDPAY_GATEKEEPER_PROGRAM_ID;
  const data = Buffer.concat([
    instructionDiscriminator("update_verifier_key"),
    params.nextActiveVerifier.toBuffer(),
  ]);

  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: params.configPda, isSigner: false, isWritable: true },
      { pubkey: params.authority, isSigner: true, isWritable: false },
    ],
    data,
  });
}

export function buildCommitResultInstruction(params: {
  configPda: PublicKey;
  requestPda: PublicKey;
  verifier: PublicKey;
  challengeHash32: Uint8Array;
  status: VerificationStatus;
  attestationDigestHex: string;
  verifierKeyId: string;
  programId?: PublicKey;
}): TransactionInstruction {
  const programId = params.programId ?? SHIELDPAY_GATEKEEPER_PROGRAM_ID;
  const data = Buffer.concat([
    instructionDiscriminator("commit_result"),
    Buffer.from(params.challengeHash32),
    Buffer.from([STATUS_TO_ANCHOR[params.status]]),
    bytes32FromHex(params.attestationDigestHex),
    Buffer.from(verifierKeyIdHashFromString(params.verifierKeyId)),
  ]);

  return new TransactionInstruction({
    programId,
    keys: [
      { pubkey: params.configPda, isSigner: false, isWritable: false },
      { pubkey: params.requestPda, isSigner: false, isWritable: true },
      { pubkey: params.verifier, isSigner: true, isWritable: false },
    ],
    data,
  });
}

export function decodeRequestAccountData(data: Buffer): DecodedRequestAccount {
  const expectedDiscriminator = accountDiscriminator("VerificationRequestAccount");
  const actualDiscriminator = data.subarray(0, 8);
  if (!actualDiscriminator.equals(expectedDiscriminator)) {
    throw new Error("Unexpected account discriminator for VerificationRequestAccount");
  }

  let offset = 8;
  const merchant = new PublicKey(data.subarray(offset, offset + 32));
  offset += 32;
  const requestIdSeed = data.subarray(offset, offset + 16);
  offset += 16;
  const challengeHash = data.subarray(offset, offset + 32);
  offset += 32;
  const statusByte = data.at(offset);
  if (statusByte === undefined) {
    throw new Error("Malformed request account data");
  }
  const status = ANCHOR_TO_STATUS[statusByte];
  offset += 1;
  if (status === undefined) {
    throw new Error("Unknown on-chain status value");
  }
  const createdAtUnix = data.readBigInt64LE(offset);
  offset += 8;
  const expiresAtUnix = data.readBigInt64LE(offset);
  offset += 8;
  const attestationDigest = data.subarray(offset, offset + 32);
  offset += 32;
  const verifierKeyIdHash = data.subarray(offset, offset + 32);
  offset += 32;
  const bump = data.at(offset);
  if (bump === undefined) {
    throw new Error("Malformed request account bump");
  }

  return {
    merchant,
    requestIdSeed,
    challengeHash,
    status,
    createdAtUnix,
    expiresAtUnix,
    attestationDigest,
    verifierKeyIdHash,
    bump,
  };
}

export class SolanaGatekeeperClient {
  public constructor(
    private readonly connection: Connection,
    private readonly programId: PublicKey = SHIELDPAY_GATEKEEPER_PROGRAM_ID,
  ) {}

  public async createRequest(params: {
    payer: Keypair;
    merchant: Keypair;
    requestId: string;
    challenge: string;
    expiresAtMs: number;
  }): Promise<PublicKey> {
    const requestSeed = requestIdSeed16FromString(params.requestId);
    const requestPda = deriveRequestPda(params.merchant.publicKey, requestSeed, this.programId);
    const ix = buildCreateRequestInstruction({
      payer: params.payer.publicKey,
      merchant: params.merchant.publicKey,
      requestPda,
      requestIdSeed16: requestSeed,
      challengeHash32: challengeHashFromRaw(params.challenge),
      expiresAtUnix: BigInt(Math.floor(params.expiresAtMs / 1000)),
      programId: this.programId,
    });
    await sendAndConfirmTransaction(this.connection, new Transaction().add(ix), [
      params.payer,
      params.merchant,
    ]);
    return requestPda;
  }

  public async commitResult(params: {
    verifier: Keypair;
    merchant: PublicKey;
    requestId: string;
    challenge: string;
    status: VerificationStatus;
    attestationDigestHex: string;
    verifierKeyId: string;
  }): Promise<string> {
    const requestPda = deriveRequestPda(
      params.merchant,
      requestIdSeed16FromString(params.requestId),
      this.programId,
    );
    const ix = buildCommitResultInstruction({
      configPda: deriveConfigPda(this.programId),
      requestPda,
      verifier: params.verifier.publicKey,
      challengeHash32: challengeHashFromRaw(params.challenge),
      status: params.status,
      attestationDigestHex: params.attestationDigestHex,
      verifierKeyId: params.verifierKeyId,
      programId: this.programId,
    });
    return sendAndConfirmTransaction(this.connection, new Transaction().add(ix), [params.verifier]);
  }

  public async readRequestStatus(
    merchant: PublicKey,
    requestId: string,
  ): Promise<VerificationStatus | null> {
    const requestPda = deriveRequestPda(merchant, requestIdSeed16FromString(requestId), this.programId);
    const info = await this.connection.getAccountInfo(requestPda);
    if (info === null) {
      return null;
    }
    return decodeRequestAccountData(info.data).status;
  }
}

function instructionDiscriminator(name: string): Buffer {
  return Buffer.from(sha256(new TextEncoder().encode(`global:${name}`)).slice(0, 8));
}

function accountDiscriminator(name: string): Buffer {
  return Buffer.from(sha256(new TextEncoder().encode(`account:${name}`)).slice(0, 8));
}

function i64Le(value: bigint): Buffer {
  const out = Buffer.alloc(8);
  out.writeBigInt64LE(value, 0);
  return out;
}

function bytes32FromHex(hex: string): Buffer {
  const normalized = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (normalized.length !== 64) {
    throw new Error("Expected 32-byte hex string");
  }
  return Buffer.from(normalized, "hex");
}
