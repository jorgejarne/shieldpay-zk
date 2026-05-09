import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey, Transaction, sendAndConfirmTransaction } from "@solana/web3.js";
import type { VerificationStatus } from "@shieldpay/shared-types";
import {
  SHIELDPAY_GATEKEEPER_PROGRAM_ID,
  SolanaGatekeeperClient,
  buildInitializeConfigInstruction,
  buildUpdateVerifierKeyInstruction,
  deriveConfigPda,
  getRpcUrl,
} from "@shieldpay/solana-gatekeeper-sdk";
import type { GatekeeperAnchoringClient } from "./index.js";

export interface SolanaAnchoringClientOptions {
  cluster: "localnet" | "devnet";
  merchantSigner: Keypair;
  verifierSigner: Keypair;
  rpcUrl?: string;
  programId?: PublicKey;
}

export class MerchantSolanaAnchoringClient implements GatekeeperAnchoringClient {
  private readonly sdkClient: SolanaGatekeeperClient;
  private readonly connection: Connection;
  private readonly programId: PublicKey;

  public constructor(private readonly options: SolanaAnchoringClientOptions) {
    this.connection = new Connection(options.rpcUrl ?? getRpcUrl(options.cluster), "confirmed");
    this.programId = options.programId ?? SHIELDPAY_GATEKEEPER_PROGRAM_ID;
    this.sdkClient = new SolanaGatekeeperClient(this.connection, this.programId);
  }

  public async ensureReady(): Promise<void> {
    await this.ensureAirdrop(this.options.merchantSigner.publicKey, 2);
    await this.ensureAirdrop(this.options.verifierSigner.publicKey, 2);
    const configPda = deriveConfigPda(this.programId);
    try {
      await sendAndConfirmTransaction(
        this.connection,
        new Transaction().add(
          buildInitializeConfigInstruction({
            payer: this.options.merchantSigner.publicKey,
            configPda,
            authority: this.options.merchantSigner.publicKey,
            activeVerifier: this.options.verifierSigner.publicKey,
            programId: this.programId,
          }),
        ),
        [this.options.merchantSigner],
      );
      console.log("[merchant-api] Solana config initialized");
    } catch {
      await sendAndConfirmTransaction(
        this.connection,
        new Transaction().add(
          buildUpdateVerifierKeyInstruction({
            configPda,
            authority: this.options.merchantSigner.publicKey,
            nextActiveVerifier: this.options.verifierSigner.publicKey,
            programId: this.programId,
          }),
        ),
        [this.options.merchantSigner],
      );
      console.log("[merchant-api] Solana verifier key updated");
    }
  }

  public async createRequestAnchor(input: {
    merchantWallet: string;
    requestId: string;
    challenge: string;
    expiresAtMs: number;
  }): Promise<void> {
    this.assertMerchantWallet(input.merchantWallet);
    await this.sdkClient.createRequest({
      payer: this.options.merchantSigner,
      merchant: this.options.merchantSigner,
      requestId: input.requestId,
      challenge: input.challenge,
      expiresAtMs: input.expiresAtMs,
    });
    console.log("[merchant-api] Solana create_request sent", { requestId: input.requestId });
  }

  public async commitResultAnchor(input: {
    merchantWallet: string;
    requestId: string;
    challenge: string;
    status: VerificationStatus;
    attestationDigestHex: string;
    verifierKeyId: string;
  }): Promise<string | null> {
    this.assertMerchantWallet(input.merchantWallet);
    const transactionSignature = await this.sdkClient.commitResult({
      verifier: this.options.verifierSigner,
      merchant: this.options.merchantSigner.publicKey,
      requestId: input.requestId,
      challenge: input.challenge,
      status: input.status,
      attestationDigestHex: input.attestationDigestHex,
      verifierKeyId: input.verifierKeyId,
    });
    console.log("[merchant-api] Solana commit_result sent", {
      requestId: input.requestId,
      status: input.status,
      transactionSignature,
    });
    console.log("[merchant-api] Solana anchoring transaction signature", {
      requestId: input.requestId,
      transactionSignature,
    });
    return transactionSignature;
  }

  public async readAnchoredStatus(input: {
    merchantWallet: string;
    requestId: string;
  }): Promise<VerificationStatus | null> {
    this.assertMerchantWallet(input.merchantWallet);
    const status = await this.sdkClient.readRequestStatus(this.options.merchantSigner.publicKey, input.requestId);
    console.log("[merchant-api] final status read from Solana", { requestId: input.requestId, status });
    return status;
  }

  private assertMerchantWallet(expectedWallet: string): void {
    if (this.options.merchantSigner.publicKey.toBase58() !== expectedWallet) {
      throw new Error("merchant wallet does not match configured merchant signer");
    }
  }

  private async ensureAirdrop(pubkey: PublicKey, sol: number): Promise<void> {
    const sig = await this.connection.requestAirdrop(pubkey, sol * LAMPORTS_PER_SOL);
    await this.connection.confirmTransaction(sig, "confirmed");
  }
}
