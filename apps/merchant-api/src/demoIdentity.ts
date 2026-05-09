import { ed25519 } from "@noble/curves/ed25519";
import type { CredentialEnvelope, ProofSubmission, VerificationRequest } from "@shieldpay/shared-types";
import { canonicalCredentialPayload, canonicalMessageForProof } from "@shieldpay/verification-core";

export interface DemoCustomerIdentity {
  subjectId: string;
  privateKeyHex: string;
  publicKeyHex: string;
}

export function generateDemoCustomerIdentity(subjectId: string): DemoCustomerIdentity {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    subjectId,
    privateKeyHex: bytesToHex(privateKey),
    publicKeyHex: bytesToHex(publicKey),
  };
}

export function createMockCredentialEnvelope(
  identity: DemoCustomerIdentity,
  issuerKeyId: string,
  nowMs: number,
): CredentialEnvelope {
  const issuerPrivateKeyHex = getDemoIssuerPrivateKeyHex();
  const unsignedCredential = {
    credentialId: `cred_${identity.subjectId}`,
    credentialType: "KYC_VERIFIED" as const,
    subjectId: identity.subjectId,
    subjectPublicKeyHex: identity.publicKeyHex,
    claims: {
      kycStatus: "VERIFIED" as const,
      country: "DE" as const,
      ageOver18: true as const,
    },
    issuerKeyId,
    issuedAtMs: nowMs,
    expiresAtMs: nowMs + 24 * 60 * 60 * 1000,
    issuerSignatureHex: "",
  };
  const issuerSignatureHex = bytesToHex(
    ed25519.sign(
      canonicalCredentialPayload(unsignedCredential),
      hexToBytes(issuerPrivateKeyHex),
    ),
  );
  return {
    ...unsignedCredential,
    issuerSignatureHex,
  };
}

export function signProofForRequest(
  request: VerificationRequest,
  credential: CredentialEnvelope,
  identity: DemoCustomerIdentity,
  signedAtMs: number,
): ProofSubmission {
  const unsigned: ProofSubmission = {
    requestId: request.requestId,
    credentialId: credential.credentialId,
    subjectId: identity.subjectId,
    challenge: request.challenge,
    signedAtMs,
    signatureHex: "",
  };
  const message = canonicalMessageForProof(request, unsigned);
  const signature = ed25519.sign(message, hexToBytes(identity.privateKeyHex));
  return {
    ...unsigned,
    signatureHex: bytesToHex(signature),
  };
}

function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    bytes[i / 2] = Number.parseInt(normalized.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function getDemoIssuerPrivateKeyHex(): string {
  const configured = process.env.SHIELDPAY_ISSUER_PRIVATE_KEY_HEX;
  if (configured !== undefined) {
    return stripHexPrefix(configured);
  }
  // DEMO_ONLY: deterministic fallback key so local demo remains runnable without extra setup.
  return "51".repeat(32);
}

export function getDemoIssuerPublicKeyHex(privateKeyHex: string = getDemoIssuerPrivateKeyHex()): string {
  return bytesToHex(ed25519.getPublicKey(hexToBytes(privateKeyHex)));
}

function stripHexPrefix(hex: string): string {
  return hex.startsWith("0x") ? hex.slice(2) : hex;
}
