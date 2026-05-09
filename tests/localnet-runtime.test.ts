import { describe, expect, it } from "vitest";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  SHIELDPAY_GATEKEEPER_PROGRAM_ID,
  buildCommitResultInstruction,
  buildCreateRequestInstruction,
  buildInitializeConfigInstruction,
  buildUpdateVerifierKeyInstruction,
  challengeHashFromRaw,
  decodeRequestAccountData,
  deriveConfigPda,
  deriveRequestPda,
  getRpcUrl,
  requestIdSeed16FromString,
} from "@shieldpay/solana-gatekeeper-sdk";

const runLocalnet = process.env.RUN_LOCALNET_TESTS === "1";
const localnetDescribe = runLocalnet ? describe : describe.skip;

localnetDescribe("localnet runtime gatekeeper flow", () => {
  it("happy path: create_request -> commit_result approved -> read status", async () => {
    const connection = new Connection(getRpcUrl("localnet"), "confirmed");
    const payer = stableAuthority();
    const merchant = Keypair.generate();
    const verifier = Keypair.generate();

    await airdrop(connection, payer.publicKey, 2);
    await airdrop(connection, merchant.publicKey, 1);
    await airdrop(connection, verifier.publicKey, 1);

    const configPda = deriveConfigPda(SHIELDPAY_GATEKEEPER_PROGRAM_ID);
    await ensureConfigWithVerifier(connection, payer, verifier.publicKey, configPda);

    const requestId = "localnet_req_happy";
    const challenge = "localnet_challenge_happy";
    const requestSeed = requestIdSeed16FromString(requestId);
    const requestPda = deriveRequestPda(merchant.publicKey, requestSeed, SHIELDPAY_GATEKEEPER_PROGRAM_ID);
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
        buildCreateRequestInstruction({
          payer: payer.publicKey,
          merchant: merchant.publicKey,
          requestPda,
          requestIdSeed16: requestSeed,
          challengeHash32: challengeHashFromRaw(challenge),
          expiresAtUnix: BigInt(Math.floor(Date.now() / 1000) + 300),
          programId: SHIELDPAY_GATEKEEPER_PROGRAM_ID,
        }),
      ),
      [payer, merchant],
    );

    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
        buildCommitResultInstruction({
          configPda,
          requestPda,
          verifier: verifier.publicKey,
          challengeHash32: challengeHashFromRaw(challenge),
          status: "APPROVED",
          attestationDigestHex: "aa".repeat(32),
          verifierKeyId: "verifier_global_v1",
          programId: SHIELDPAY_GATEKEEPER_PROGRAM_ID,
        }),
      ),
      [verifier],
    );

    const account = await connection.getAccountInfo(requestPda);
    expect(account).not.toBeNull();
    const decoded = decodeRequestAccountData(account!.data);
    expect(decoded.status).toBe("APPROVED");
  });

  it("authorization failure: unauthorized verifier cannot commit result", async () => {
    const connection = new Connection(getRpcUrl("localnet"), "confirmed");
    const payer = stableAuthority();
    const merchant = Keypair.generate();
    const authorizedVerifier = Keypair.generate();
    const unauthorizedVerifier = Keypair.generate();

    await airdrop(connection, payer.publicKey, 2);
    await airdrop(connection, merchant.publicKey, 1);
    await airdrop(connection, authorizedVerifier.publicKey, 1);
    await airdrop(connection, unauthorizedVerifier.publicKey, 1);

    const configPda = deriveConfigPda(SHIELDPAY_GATEKEEPER_PROGRAM_ID);
    await ensureConfigWithVerifier(connection, payer, authorizedVerifier.publicKey, configPda);

    const requestId = "localnet_req_auth";
    const challenge = "localnet_challenge_auth";
    const requestSeed = requestIdSeed16FromString(requestId);
    const requestPda = deriveRequestPda(merchant.publicKey, requestSeed, SHIELDPAY_GATEKEEPER_PROGRAM_ID);
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
        buildCreateRequestInstruction({
          payer: payer.publicKey,
          merchant: merchant.publicKey,
          requestPda,
          requestIdSeed16: requestSeed,
          challengeHash32: challengeHashFromRaw(challenge),
          expiresAtUnix: BigInt(Math.floor(Date.now() / 1000) + 300),
          programId: SHIELDPAY_GATEKEEPER_PROGRAM_ID,
        }),
      ),
      [payer, merchant],
    );

    await expect(
      sendAndConfirmTransaction(
        connection,
        new Transaction().add(
          buildCommitResultInstruction({
            configPda,
            requestPda,
            verifier: unauthorizedVerifier.publicKey,
            challengeHash32: challengeHashFromRaw(challenge),
            status: "APPROVED",
            attestationDigestHex: "bb".repeat(32),
            verifierKeyId: "verifier_global_v1",
            programId: SHIELDPAY_GATEKEEPER_PROGRAM_ID,
          }),
        ),
        [unauthorizedVerifier],
      ),
    ).rejects.toThrow();
  });

  it("invalid state transition: finalized request cannot be committed twice", async () => {
    const connection = new Connection(getRpcUrl("localnet"), "confirmed");
    const payer = stableAuthority();
    const merchant = Keypair.generate();
    const verifier = Keypair.generate();

    await airdrop(connection, payer.publicKey, 2);
    await airdrop(connection, merchant.publicKey, 1);
    await airdrop(connection, verifier.publicKey, 1);

    const configPda = deriveConfigPda(SHIELDPAY_GATEKEEPER_PROGRAM_ID);
    await ensureConfigWithVerifier(connection, payer, verifier.publicKey, configPda);

    const requestId = "localnet_req_state";
    const challenge = "localnet_challenge_state";
    const requestSeed = requestIdSeed16FromString(requestId);
    const requestPda = deriveRequestPda(merchant.publicKey, requestSeed, SHIELDPAY_GATEKEEPER_PROGRAM_ID);
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
        buildCreateRequestInstruction({
          payer: payer.publicKey,
          merchant: merchant.publicKey,
          requestPda,
          requestIdSeed16: requestSeed,
          challengeHash32: challengeHashFromRaw(challenge),
          expiresAtUnix: BigInt(Math.floor(Date.now() / 1000) + 300),
          programId: SHIELDPAY_GATEKEEPER_PROGRAM_ID,
        }),
      ),
      [payer, merchant],
    );

    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
        buildCommitResultInstruction({
          configPda,
          requestPda,
          verifier: verifier.publicKey,
          challengeHash32: challengeHashFromRaw(challenge),
          status: "REJECTED",
          attestationDigestHex: "cc".repeat(32),
          verifierKeyId: "verifier_global_v1",
          programId: SHIELDPAY_GATEKEEPER_PROGRAM_ID,
        }),
      ),
      [verifier],
    );

    await expect(
      sendAndConfirmTransaction(
        connection,
        new Transaction().add(
          buildCommitResultInstruction({
            configPda,
            requestPda,
            verifier: verifier.publicKey,
            challengeHash32: challengeHashFromRaw(challenge),
            status: "APPROVED",
            attestationDigestHex: "dd".repeat(32),
            verifierKeyId: "verifier_global_v1",
            programId: SHIELDPAY_GATEKEEPER_PROGRAM_ID,
          }),
        ),
        [verifier],
      ),
    ).rejects.toThrow();
  });
});

async function airdrop(connection: Connection, pubkey: PublicKey, sol: number): Promise<void> {
  const sig = await connection.requestAirdrop(pubkey, sol * 1_000_000_000);
  await connection.confirmTransaction(sig, "confirmed");
}

async function ensureConfigWithVerifier(
  connection: Connection,
  authority: Keypair,
  activeVerifier: PublicKey,
  configPda: PublicKey,
): Promise<void> {
  try {
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
        buildInitializeConfigInstruction({
          payer: authority.publicKey,
          configPda,
          authority: authority.publicKey,
          activeVerifier,
          programId: SHIELDPAY_GATEKEEPER_PROGRAM_ID,
        }),
      ),
      [authority],
    );
    return;
  } catch {
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
        buildUpdateVerifierKeyInstruction({
          configPda,
          authority: authority.publicKey,
          nextActiveVerifier: activeVerifier,
          programId: SHIELDPAY_GATEKEEPER_PROGRAM_ID,
        }),
      ),
      [authority],
    );
  }
}

function stableAuthority(): Keypair {
  const seed = new Uint8Array(32).fill(7);
  return Keypair.fromSeed(seed);
}
