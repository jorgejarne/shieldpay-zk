import { ed25519 } from "@noble/curves/ed25519";
import { createHash } from "node:crypto";

import type {
  CredentialEnvelope,
  ProofSubmission,
  VerificationRequest,
  VerificationResult,
} from "@shieldpay/shared-types";

export interface VerificationDependencies {
  nowMs: () => number;
  verificationWindowMs: number;
  revokedCredentialIds: ReadonlySet<string>;
  trustedIssuerPublicKeysByKeyId: Readonly<Record<string, string>>;
}

export interface VerificationDecisionInput {
  request: VerificationRequest | null;
  credential: CredentialEnvelope | null;
  submission: ProofSubmission;
}

export async function verifyProofSubmission(
  deps: VerificationDependencies,
  input: VerificationDecisionInput,
): Promise<VerificationResult> {
  const nowMs = deps.nowMs();
  const requestId = input.submission.requestId;

  if (input.request === null) {
    return rejection(nowMs, deps.verificationWindowMs, requestId, input.submission.subjectId, "REQUEST_NOT_FOUND");
  }

  const request = input.request;
  const subjectId = input.submission.subjectId;

  if (nowMs > request.expiresAtMs) {
    return rejection(nowMs, deps.verificationWindowMs, request.requestId, subjectId, "REQUEST_EXPIRED");
  }

  if (input.credential === null) {
    return rejection(nowMs, deps.verificationWindowMs, request.requestId, subjectId, "SIGNATURE_INVALID");
  }

  const credential = input.credential;

  if (credential.credentialType !== request.requiredCredentialType) {
    return rejection(nowMs, deps.verificationWindowMs, request.requestId, subjectId, "CREDENTIAL_TYPE_MISMATCH");
  }

  if (credential.claims.kycStatus !== "VERIFIED") {
    return rejection(nowMs, deps.verificationWindowMs, request.requestId, subjectId, "KYC_NOT_VERIFIED");
  }

  if (credential.claims.ageOver18 !== true) {
    return rejection(nowMs, deps.verificationWindowMs, request.requestId, subjectId, "AGE_CHECK_FAILED");
  }

  if (credential.subjectId !== input.submission.subjectId) {
    return rejection(nowMs, deps.verificationWindowMs, request.requestId, subjectId, "SUBJECT_MISMATCH");
  }

  if (credential.expiresAtMs < nowMs) {
    return rejection(nowMs, deps.verificationWindowMs, request.requestId, subjectId, "CREDENTIAL_EXPIRED");
  }

  if (deps.revokedCredentialIds.has(credential.credentialId)) {
    return rejection(nowMs, deps.verificationWindowMs, request.requestId, subjectId, "CREDENTIAL_REVOKED");
  }

  const issuerPublicKeyHex = deps.trustedIssuerPublicKeysByKeyId[credential.issuerKeyId];
  if (issuerPublicKeyHex === undefined) {
    return rejection(nowMs, deps.verificationWindowMs, request.requestId, subjectId, "ISSUER_SIGNATURE_INVALID");
  }
  const issuerSignatureValid = ed25519.verify(
    bytesFromHex(credential.issuerSignatureHex),
    canonicalCredentialPayload(credential),
    bytesFromHex(issuerPublicKeyHex),
  );
  if (!issuerSignatureValid) {
    return rejection(nowMs, deps.verificationWindowMs, request.requestId, subjectId, "ISSUER_SIGNATURE_INVALID");
  }

  if (input.submission.challenge !== request.challenge) {
    return rejection(nowMs, deps.verificationWindowMs, request.requestId, subjectId, "CHALLENGE_MISMATCH");
  }

  if (input.submission.signedAtMs + deps.verificationWindowMs < nowMs) {
    return rejection(nowMs, deps.verificationWindowMs, request.requestId, subjectId, "SUBMISSION_STALE");
  }

  const canonicalMessage = canonicalMessageForProof(request, input.submission);
  const signature = bytesFromHex(input.submission.signatureHex);
  const publicKey = bytesFromHex(credential.subjectPublicKeyHex);

  const isValid = ed25519.verify(signature, canonicalMessage, publicKey);
  if (!isValid) {
    return rejection(nowMs, deps.verificationWindowMs, request.requestId, subjectId, "SIGNATURE_INVALID");
  }

  const approved: VerificationResult = {
    requestId: request.requestId,
    subjectId,
    status: "APPROVED",
    reasonCode: "OK",
    decidedAtMs: nowMs,
    verificationWindowMs: deps.verificationWindowMs,
    attestationDigestHex: "",
  };
  approved.attestationDigestHex = computeAttestationDigestHex(approved);
  return approved;
}

export function canonicalCredentialPayload(credential: CredentialEnvelope): Uint8Array {
  const serialized = [
    "shieldpay.credential.kyc.v1",
    credential.credentialId,
    credential.credentialType,
    credential.subjectId,
    credential.subjectPublicKeyHex,
    credential.claims.kycStatus,
    credential.claims.country,
    credential.claims.ageOver18 ? "true" : "false",
    credential.issuerKeyId,
    String(credential.issuedAtMs),
    String(credential.expiresAtMs),
  ].join("|");
  return new TextEncoder().encode(serialized);
}

export function canonicalMessageForProof(
  request: VerificationRequest,
  submission: ProofSubmission,
): Uint8Array {
  const message = [
    "shieldpay.verification.v1",
    request.requestId,
    request.challenge,
    submission.subjectId,
    String(submission.signedAtMs),
  ].join("|");
  return new TextEncoder().encode(message);
}

export function computeAttestationDigestHex(result: Omit<VerificationResult, "attestationDigestHex">): string {
  const serialized = JSON.stringify({
    requestId: result.requestId,
    subjectId: result.subjectId,
    status: result.status,
    reasonCode: result.reasonCode,
    decidedAtMs: result.decidedAtMs,
    verificationWindowMs: result.verificationWindowMs,
  });
  return createHash("sha256").update(serialized).digest("hex");
}

function rejection(
  decidedAtMs: number,
  verificationWindowMs: number,
  requestId: string,
  subjectId: string,
  reasonCode: VerificationResult["reasonCode"],
): VerificationResult {
  const rejected: VerificationResult = {
    requestId,
    subjectId,
    status: reasonCode === "REQUEST_EXPIRED" ? "EXPIRED" : "REJECTED",
    reasonCode,
    decidedAtMs,
    verificationWindowMs,
    attestationDigestHex: "",
  };
  rejected.attestationDigestHex = computeAttestationDigestHex(rejected);
  return rejected;
}

function bytesFromHex(hex: string): Uint8Array {
  const normalized = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (normalized.length % 2 !== 0) {
    throw new Error("Hex string length must be even");
  }
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    const byte = Number.parseInt(normalized.slice(i, i + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error("Hex contains invalid characters");
    }
    bytes[i / 2] = byte;
  }
  return bytes;
}
