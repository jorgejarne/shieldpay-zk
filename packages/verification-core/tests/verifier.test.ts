import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";

import type { CredentialEnvelope, ProofSubmission, VerificationRequest } from "@shieldpay/shared-types";
import { canonicalCredentialPayload, canonicalMessageForProof, verifyProofSubmission } from "../src/index.js";

const subjectPrivateKey = hexToBytes("1f".repeat(32));
const subjectPublicKeyHex = bytesToHex(ed25519.getPublicKey(subjectPrivateKey));
const issuerPrivateKey = hexToBytes("2a".repeat(32));
const issuerPublicKeyHex = bytesToHex(ed25519.getPublicKey(issuerPrivateKey));

function baseRequest(nowMs: number): VerificationRequest {
  return {
    requestId: "req_123",
    merchantId: "merchant_abc",
    merchantWallet: "merchant_wallet_pubkey",
    challenge: "challenge_nonce_1",
    createdAtMs: nowMs - 1_000,
    expiresAtMs: nowMs + 60_000,
    requiredCredentialType: "KYC_VERIFIED",
  };
}

function baseCredential(nowMs: number): CredentialEnvelope {
  const unsignedCredential = {
    credentialId: "cred_1",
    credentialType: "KYC_VERIFIED" as const,
    subjectId: "subject_77",
    subjectPublicKeyHex,
    claims: {
      kycStatus: "VERIFIED" as const,
      country: "DE" as const,
      ageOver18: true as const,
    },
    issuerKeyId: "issuer_1",
    issuedAtMs: nowMs - 10_000,
    expiresAtMs: nowMs + 360_000,
    issuerSignatureHex: "",
  };
  return {
    ...unsignedCredential,
    issuerSignatureHex: bytesToHex(ed25519.sign(canonicalCredentialPayload(unsignedCredential), issuerPrivateKey)),
  };
}

function signSubmission(request: VerificationRequest): ProofSubmission {
  const unsigned: ProofSubmission = {
    requestId: request.requestId,
    credentialId: "cred_1",
    subjectId: "subject_77",
    challenge: request.challenge,
    signedAtMs: request.createdAtMs + 500,
    signatureHex: "",
  };
  const message = canonicalMessageForProof(request, unsigned);
  const signature = ed25519.sign(message, subjectPrivateKey);
  return { ...unsigned, signatureHex: bytesToHex(signature) };
}

describe("verifyProofSubmission", () => {
  it("approves valid proof with deterministic attestation digest", async () => {
    const nowMs = 1_720_000_000_000;
    const request = baseRequest(nowMs);
    const credential = baseCredential(nowMs);
    const submission = signSubmission(request);

    const result = await verifyProofSubmission(
      {
        nowMs: () => nowMs,
        verificationWindowMs: 120_000,
        revokedCredentialIds: new Set<string>(),
        trustedIssuerPublicKeysByKeyId: { issuer_1: issuerPublicKeyHex },
      },
      { request, credential, submission },
    );

    expect(result.status).toBe("APPROVED");
    expect(result.reasonCode).toBe("OK");
    expect(result.attestationDigestHex.length).toBe(64);
  });

  it("rejects replayed stale submission", async () => {
    const nowMs = 1_720_000_000_000;
    const request = baseRequest(nowMs);
    const credential = baseCredential(nowMs);
    const validSubmission = signSubmission(request);
    const staleSubmission = {
      ...validSubmission,
      signedAtMs: nowMs - 121_000,
      signatureHex: bytesToHex(
        ed25519.sign(
          canonicalMessageForProof(request, {
            ...validSubmission,
            signedAtMs: nowMs - 121_000,
          }),
          subjectPrivateKey,
        ),
      ),
    };

    const result = await verifyProofSubmission(
      {
        nowMs: () => nowMs,
        verificationWindowMs: 120_000,
        revokedCredentialIds: new Set<string>(),
        trustedIssuerPublicKeysByKeyId: { issuer_1: issuerPublicKeyHex },
      },
      { request, credential, submission: staleSubmission },
    );

    expect(result.status).toBe("REJECTED");
    expect(result.reasonCode).toBe("SUBMISSION_STALE");
  });

  it("rejects invalid issuer signature", async () => {
    const nowMs = 1_720_000_000_000;
    const request = baseRequest(nowMs);
    const credential = { ...baseCredential(nowMs), issuerSignatureHex: "00".repeat(64) };
    const submission = signSubmission(request);

    const result = await verifyProofSubmission(
      {
        nowMs: () => nowMs,
        verificationWindowMs: 120_000,
        revokedCredentialIds: new Set<string>(),
        trustedIssuerPublicKeysByKeyId: { issuer_1: issuerPublicKeyHex },
      },
      { request, credential, submission },
    );

    expect(result.status).toBe("REJECTED");
    expect(result.reasonCode).toBe("ISSUER_SIGNATURE_INVALID");
  });
});

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
