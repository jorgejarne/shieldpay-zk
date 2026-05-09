import type {
  CredentialEnvelope,
  ProofVerificationResponse,
  ProofSubmission,
  VerificationStatus,
  VerificationRequest,
  VerificationStatusView,
} from "@shieldpay/shared-types";
import { ProofService } from "@shieldpay/proof-service";
import { randomUUID } from "node:crypto";

export interface MerchantCreateRequestInput {
  merchantId: string;
  merchantWallet: string;
  requiredCredentialType: VerificationRequest["requiredCredentialType"];
  ttlMs: number;
}

export interface GatekeeperAnchoringClient {
  createRequestAnchor(input: {
    merchantWallet: string;
    requestId: string;
    challenge: string;
    expiresAtMs: number;
  }): Promise<void>;
  commitResultAnchor(input: {
    merchantWallet: string;
    requestId: string;
    challenge: string;
    status: VerificationStatus;
    attestationDigestHex: string;
    verifierKeyId: string;
  }): Promise<string | null>;
  readAnchoredStatus(input: { merchantWallet: string; requestId: string }): Promise<VerificationStatus | null>;
}

export class MerchantVerificationService {
  private readonly requests = new Map<string, VerificationRequest>();
  private readonly statuses = new Map<string, VerificationStatusView>();
  private readonly requestById = new Map<string, VerificationRequest>();

  public constructor(
    private readonly proofService: ProofService,
    private readonly nowMs: () => number,
    private readonly anchoringClient?: GatekeeperAnchoringClient,
  ) {}

  public async createVerificationRequest(input: MerchantCreateRequestInput): Promise<VerificationRequest> {
    const createdAtMs = this.nowMs();
    const request: VerificationRequest = {
      requestId: `req_${randomUUID()}`,
      merchantId: input.merchantId,
      merchantWallet: input.merchantWallet,
      challenge: `challenge_${randomUUID()}`,
      createdAtMs,
      expiresAtMs: createdAtMs + input.ttlMs,
      requiredCredentialType: input.requiredCredentialType,
    };

    this.requests.set(request.requestId, request);
    this.requestById.set(request.requestId, request);
    this.statuses.set(request.requestId, {
      requestId: request.requestId,
      merchantId: request.merchantId,
      status: "PENDING",
      attestationDigestHex: null,
      verifierKeyId: null,
      updatedAtMs: createdAtMs,
    });

    if (this.anchoringClient !== undefined) {
      await this.anchoringClient.createRequestAnchor({
        merchantWallet: request.merchantWallet,
        requestId: request.requestId,
        challenge: request.challenge,
        expiresAtMs: request.expiresAtMs,
      });
    }

    return request;
  }

  public async submitProof(
    requestId: string,
    credential: CredentialEnvelope,
    submission: ProofSubmission,
  ): Promise<{ attestation: ProofVerificationResponse; transactionSignature: string | null }> {
    const request = this.requests.get(requestId);
    if (request === undefined) {
      throw new Error("request not found");
    }

    const signedAttestation = await this.proofService.verify({
      request,
      credential,
      submission,
    });

    this.statuses.set(requestId, {
      requestId,
      merchantId: request.merchantId,
      status: signedAttestation.result.status,
      attestationDigestHex: signedAttestation.result.attestationDigestHex,
      verifierKeyId: signedAttestation.verifierKeyId,
      updatedAtMs: this.nowMs(),
    });

    let transactionSignature: string | null = null;
    if (this.anchoringClient !== undefined) {
      transactionSignature = await this.anchoringClient.commitResultAnchor({
        merchantWallet: request.merchantWallet,
        requestId,
        challenge: request.challenge,
        status: signedAttestation.result.status,
        attestationDigestHex: signedAttestation.result.attestationDigestHex,
        verifierKeyId: signedAttestation.verifierKeyId,
      });
    }

    return { attestation: signedAttestation, transactionSignature };
  }

  public getRequest(requestId: string): VerificationRequest | null {
    return this.requestById.get(requestId) ?? null;
  }

  public getVerificationStatus(requestId: string): VerificationStatusView | null {
    const status = this.statuses.get(requestId);
    const request = this.requests.get(requestId);
    if (status === undefined || request === undefined) {
      return null;
    }

    if (status.status === "PENDING" && this.nowMs() > request.expiresAtMs) {
      const expired: VerificationStatusView = {
        ...status,
        status: "EXPIRED",
        updatedAtMs: this.nowMs(),
      };
      this.statuses.set(requestId, expired);
      return expired;
    }

    return status;
  }

  public async getAnchoredVerificationStatus(requestId: string): Promise<VerificationStatus | null> {
    if (this.anchoringClient === undefined) {
      return null;
    }
    const request = this.requests.get(requestId);
    if (request === undefined) {
      return null;
    }
    return this.anchoringClient.readAnchoredStatus({
      merchantWallet: request.merchantWallet,
      requestId,
    });
  }
}

export { MerchantSolanaAnchoringClient } from "./solanaAnchoringClient.js";
export {
  createMockCredentialEnvelope,
  getDemoIssuerPrivateKeyHex,
  getDemoIssuerPublicKeyHex,
  generateDemoCustomerIdentity,
  signProofForRequest,
  type DemoCustomerIdentity,
} from "./demoIdentity.js";
