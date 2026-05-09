import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";

import type { CredentialEnvelope, ProofSubmission, VerificationStatus } from "@shieldpay/shared-types";
import { canonicalCredentialPayload, canonicalMessageForProof } from "@shieldpay/verification-core";
import { type GatekeeperAnchoringClient, MerchantVerificationService } from "../src/index.js";
import { ProofService, ShieldPaySingleIssuerPolicy } from "@shieldpay/proof-service";

let nowMs = 1_720_000_000_000;
const userPrivateKey = hexToBytes("12".repeat(32));
const verifierPrivateKeyHex = "34".repeat(32);
const userPublicKeyHex = bytesToHex(ed25519.getPublicKey(userPrivateKey));
const issuerPrivateKey = hexToBytes("56".repeat(32));
const issuerPublicKeyHex = bytesToHex(ed25519.getPublicKey(issuerPrivateKey));

describe("merchant verification flow", () => {
  it("marks pending request as expired when ttl has elapsed", async () => {
    nowMs = 1_720_000_000_000;
    const proofService = new ProofService({
      issuerPolicy: new ShieldPaySingleIssuerPolicy("shieldpay_issuer_v1"),
      verifierKeyId: "verifier_global_v1",
      verifierPrivateKeyHex,
      nowMs: () => nowMs,
      verificationWindowMs: 120_000,
      revokedCredentialIds: new Set<string>(),
      trustedIssuerPublicKeysByKeyId: { shieldpay_issuer_v1: issuerPublicKeyHex },
    });
    const merchantService = new MerchantVerificationService(proofService, () => nowMs);

    const request = await merchantService.createVerificationRequest({
      merchantId: "merchant_0",
      merchantWallet: "merchant_wallet_0",
      requiredCredentialType: "KYC_VERIFIED",
      ttlMs: 1000,
    });

    nowMs += 2000;
    expect(merchantService.getVerificationStatus(request.requestId)?.status).toBe("EXPIRED");
  });

  it("creates request, verifies proof, and transitions PENDING to APPROVED", async () => {
    nowMs = 1_720_000_000_000;
    const anchoringClient = new InMemoryAnchoringClient();
    const proofService = new ProofService({
      issuerPolicy: new ShieldPaySingleIssuerPolicy("shieldpay_issuer_v1"),
      verifierKeyId: "verifier_global_v1",
      verifierPrivateKeyHex,
      nowMs: () => nowMs,
      verificationWindowMs: 120_000,
      revokedCredentialIds: new Set<string>(),
      trustedIssuerPublicKeysByKeyId: { shieldpay_issuer_v1: issuerPublicKeyHex },
    });

    const merchantService = new MerchantVerificationService(proofService, () => nowMs, anchoringClient);

    const request = await merchantService.createVerificationRequest({
      merchantId: "merchant_1",
      merchantWallet: "merchant_wallet_abc",
      requiredCredentialType: "KYC_VERIFIED",
      ttlMs: 300_000,
    });

    expect(merchantService.getVerificationStatus(request.requestId)?.status).toBe("PENDING");
    expect(await merchantService.getAnchoredVerificationStatus(request.requestId)).toBe("PENDING");

    const unsignedCredential = {
      credentialId: "cred_1",
      credentialType: "KYC_VERIFIED" as const,
      subjectId: "subject_1",
      subjectPublicKeyHex: userPublicKeyHex,
      claims: {
        kycStatus: "VERIFIED" as const,
        country: "DE" as const,
        ageOver18: true as const,
      },
      issuerKeyId: "shieldpay_issuer_v1",
      issuedAtMs: nowMs - 10_000,
      expiresAtMs: nowMs + 300_000,
      issuerSignatureHex: "",
    };
    const credential: CredentialEnvelope = {
      ...unsignedCredential,
      issuerSignatureHex: bytesToHex(
        ed25519.sign(canonicalCredentialPayload(unsignedCredential), issuerPrivateKey),
      ),
    };

    const unsignedSubmission: Omit<ProofSubmission, "signatureHex"> = {
      requestId: request.requestId,
      credentialId: credential.credentialId,
      subjectId: credential.subjectId,
      challenge: request.challenge,
      signedAtMs: nowMs,
    };

    const signature = ed25519.sign(
      canonicalMessageForProof(request, {
        ...unsignedSubmission,
        signatureHex: "",
      }),
      userPrivateKey,
    );

    const { attestation } = await merchantService.submitProof(request.requestId, credential, {
      ...unsignedSubmission,
      signatureHex: bytesToHex(signature),
    });

    expect(attestation.verifierKeyId).toBe("verifier_global_v1");
    expect(attestation.result.status).toBe("APPROVED");

    const finalStatus = merchantService.getVerificationStatus(request.requestId);
    expect(finalStatus?.status).toBe("APPROVED");
    expect(finalStatus?.verifierKeyId).toBe("verifier_global_v1");
    expect(finalStatus?.attestationDigestHex).toBe(attestation.result.attestationDigestHex);
    expect(await merchantService.getAnchoredVerificationStatus(request.requestId)).toBe("APPROVED");
  });

  it("rejects credential from non-shieldpay issuer", async () => {
    nowMs = 1_720_000_000_000;
    const proofService = new ProofService({
      issuerPolicy: new ShieldPaySingleIssuerPolicy("shieldpay_issuer_v1"),
      verifierKeyId: "verifier_global_v1",
      verifierPrivateKeyHex,
      nowMs: () => nowMs,
      verificationWindowMs: 120_000,
      revokedCredentialIds: new Set<string>(),
      trustedIssuerPublicKeysByKeyId: { shieldpay_issuer_v1: issuerPublicKeyHex },
    });

    const anchoringClient = new InMemoryAnchoringClient();
    const merchantService = new MerchantVerificationService(proofService, () => nowMs, anchoringClient);

    const request = await merchantService.createVerificationRequest({
      merchantId: "merchant_2",
      merchantWallet: "merchant_wallet_xyz",
      requiredCredentialType: "KYC_VERIFIED",
      ttlMs: 300_000,
    });

    const unsignedCredential = {
      credentialId: "cred_2",
      credentialType: "KYC_VERIFIED" as const,
      subjectId: "subject_2",
      subjectPublicKeyHex: userPublicKeyHex,
      claims: {
        kycStatus: "VERIFIED" as const,
        country: "DE" as const,
        ageOver18: true as const,
      },
      issuerKeyId: "untrusted_issuer",
      issuedAtMs: nowMs - 10_000,
      expiresAtMs: nowMs + 300_000,
      issuerSignatureHex: "",
    };
    const credential: CredentialEnvelope = {
      ...unsignedCredential,
      issuerSignatureHex: bytesToHex(
        ed25519.sign(canonicalCredentialPayload(unsignedCredential), issuerPrivateKey),
      ),
    };

    const submission: ProofSubmission = {
      requestId: request.requestId,
      credentialId: credential.credentialId,
      subjectId: credential.subjectId,
      challenge: request.challenge,
      signedAtMs: nowMs,
      signatureHex: "00",
    };

    const { attestation } = await merchantService.submitProof(request.requestId, credential, submission);

    expect(attestation.result.status).toBe("REJECTED");
    expect(merchantService.getVerificationStatus(request.requestId)?.status).toBe("REJECTED");
    expect(await merchantService.getAnchoredVerificationStatus(request.requestId)).toBe("REJECTED");
  });
});

class InMemoryAnchoringClient implements GatekeeperAnchoringClient {
  private readonly statuses = new Map<string, VerificationStatus>();

  public async createRequestAnchor(input: {
    merchantWallet: string;
    requestId: string;
    challenge: string;
    expiresAtMs: number;
  }): Promise<void> {
    this.statuses.set(this.key(input.merchantWallet, input.requestId), "PENDING");
  }

  public async commitResultAnchor(input: {
    merchantWallet: string;
    requestId: string;
    challenge: string;
    status: VerificationStatus;
    attestationDigestHex: string;
    verifierKeyId: string;
  }): Promise<string | null> {
    this.statuses.set(this.key(input.merchantWallet, input.requestId), input.status);
    return null;
  }

  public async readAnchoredStatus(input: {
    merchantWallet: string;
    requestId: string;
  }): Promise<VerificationStatus | null> {
    return this.statuses.get(this.key(input.merchantWallet, input.requestId)) ?? null;
  }

  private key(merchantWallet: string, requestId: string): string {
    return `${merchantWallet}:${requestId}`;
  }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
