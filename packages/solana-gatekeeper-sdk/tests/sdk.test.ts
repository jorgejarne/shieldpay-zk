import { describe, expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha2";
import { Keypair } from "@solana/web3.js";

import {
  SHIELDPAY_GATEKEEPER_PROGRAM_ID,
  buildInitializeConfigInstruction,
  buildUpdateVerifierKeyInstruction,
  buildCommitResultInstruction,
  buildCreateRequestInstruction,
  challengeHashFromRaw,
  decodeRequestAccountData,
  deriveRequestPda,
  requestIdSeed16FromString,
} from "../src/index.js";

describe("solana gatekeeper sdk", () => {
  it("derives deterministic request PDA", () => {
    const merchant = Keypair.generate().publicKey;
    const seed = requestIdSeed16FromString("req_abc");
    const pdaA = deriveRequestPda(merchant, seed);
    const pdaB = deriveRequestPda(merchant, seed);
    expect(pdaA.toBase58()).toBe(pdaB.toBase58());
  });

  it("builds create and commit instructions with expected program id", () => {
    const payer = Keypair.generate().publicKey;
    const merchant = Keypair.generate().publicKey;
    const verifier = Keypair.generate().publicKey;
    const requestIdSeed16 = requestIdSeed16FromString("req_1");
    const requestPda = deriveRequestPda(merchant, requestIdSeed16);
    const challengeHash = challengeHashFromRaw("challenge_1");

    const createIx = buildCreateRequestInstruction({
      payer,
      merchant,
      requestPda,
      requestIdSeed16,
      challengeHash32: challengeHash,
      expiresAtUnix: BigInt(1_900_000_000),
    });
    const commitIx = buildCommitResultInstruction({
      configPda: Keypair.generate().publicKey,
      requestPda,
      verifier,
      challengeHash32: challengeHash,
      status: "APPROVED",
      attestationDigestHex: "11".repeat(32),
      verifierKeyId: "verifier_global_v1",
    });

    expect(createIx.programId.toBase58()).toBe(SHIELDPAY_GATEKEEPER_PROGRAM_ID.toBase58());
    expect(commitIx.programId.toBase58()).toBe(SHIELDPAY_GATEKEEPER_PROGRAM_ID.toBase58());
    expect(createIx.data.length).toBe(8 + 16 + 32 + 8);
    expect(commitIx.data.length).toBe(8 + 32 + 1 + 32 + 32);

    const initIx = buildInitializeConfigInstruction({
      payer,
      configPda: Keypair.generate().publicKey,
      authority: payer,
      activeVerifier: verifier,
    });
    expect(initIx.programId.toBase58()).toBe(SHIELDPAY_GATEKEEPER_PROGRAM_ID.toBase58());
    expect(initIx.data.length).toBe(8 + 32 + 32);

    const updateIx = buildUpdateVerifierKeyInstruction({
      configPda: Keypair.generate().publicKey,
      authority: payer,
      nextActiveVerifier: verifier,
    });
    expect(updateIx.programId.toBase58()).toBe(SHIELDPAY_GATEKEEPER_PROGRAM_ID.toBase58());
    expect(updateIx.data.length).toBe(8 + 32);
  });

  it("decodes request account payload status", () => {
    const merchant = Keypair.generate().publicKey;
    const requestSeed = requestIdSeed16FromString("req_decode");
    const challengeHash = challengeHashFromRaw("challenge_decode");
    const discriminator = Buffer.from(
      sha256(new TextEncoder().encode("account:VerificationRequestAccount")).slice(0, 8),
    );
    const data = Buffer.concat([
      discriminator,
      merchant.toBuffer(),
      Buffer.from(requestSeed),
      Buffer.from(challengeHash),
      Buffer.from([1]),
      i64Le(BigInt(1_800_000_000)),
      i64Le(BigInt(1_800_000_900)),
      Buffer.from("22".repeat(32), "hex"),
      Buffer.from("33".repeat(32), "hex"),
      Buffer.from([255]),
    ]);

    const decoded = decodeRequestAccountData(data);
    expect(decoded.status).toBe("APPROVED");
    expect(decoded.bump).toBe(255);
  });
});

function i64Le(value: bigint): Buffer {
  const out = Buffer.alloc(8);
  out.writeBigInt64LE(value, 0);
  return out;
}
