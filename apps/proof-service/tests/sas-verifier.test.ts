import { describe, expect, it } from "vitest";

import type { CredentialEnvelope, ProofSubmission, VerificationRequest } from "@shieldpay/shared-types";
import {
  type SasAttestation,
  type SasAttestationProvider,
  SasCredentialVerifier,
} from "../src/index.js";

const baseRequest: VerificationRequest = {
  requestId: "req_sas_1",
  merchantId: "merchant_sas",
  merchantWallet: "merchant_wallet",
  challenge: "challenge_123",
  createdAtMs: 1_700_000_000_000,
  expiresAtMs: 1_800_000_000_000,
  requiredCredentialType: "KYC_VERIFIED",
};

const baseCredential: CredentialEnvelope = {
  credentialId: "cred_sas",
  credentialType: "KYC_VERIFIED",
  subjectId: "buyer_wallet_1",
  subjectPublicKeyHex: "ab".repeat(32),
  claims: {
    kycStatus: "VERIFIED",
    country: "DE",
    ageOver18: true,
  },
  issuerKeyId: "issuer_1",
  issuedAtMs: 1_700_000_000_000,
  expiresAtMs: 1_800_000_000_000,
  issuerSignatureHex: "cd".repeat(64),
};

const baseSubmission: ProofSubmission = {
  requestId: baseRequest.requestId,
  credentialId: baseCredential.credentialId,
  subjectId: "buyer_wallet_1",
  challenge: baseRequest.challenge,
  signedAtMs: 1_700_000_100_000,
  signatureHex: "ef".repeat(64),
};

describe("SasCredentialVerifier", () => {
  it("approves when trusted issuer and policy checks pass", async () => {
    const verifier = createVerifier({
      id: "sas_att_1",
      subjectWallet: "buyer_wallet_1",
      issuer: "trusted_issuer",
      schemaType: "KYC_VERIFIED",
      claims: {
        ageOver18: true,
        country: "DE",
      },
      validUntilMs: 1_800_000_000_000,
    });

    const outcome = await verifier.verify({
      request: baseRequest,
      credential: baseCredential,
      submission: baseSubmission,
    });

    expect(outcome.result.status).toBe("APPROVED");
    expect(outcome.result.reasonCode).toBe("OK");
    expect(outcome.verificationTrace.issuerTrusted).toBe(true);
    expect(outcome.verificationTrace.personalDataStoredOnChain).toBe(false);
  });

  it("rejects when no SAS attestation is found", async () => {
    const verifier = createVerifier(null);
    const outcome = await verifier.verify({
      request: baseRequest,
      credential: baseCredential,
      submission: baseSubmission,
    });
    expect(outcome.result.status).toBe("REJECTED");
    expect(outcome.result.reasonCode).toBe("SIGNATURE_INVALID");
  });

  it("rejects when issuer is not trusted", async () => {
    const verifier = createVerifier({
      id: "sas_att_2",
      subjectWallet: "buyer_wallet_1",
      issuer: "untrusted_issuer",
      schemaType: "KYC_VERIFIED",
      claims: {
        ageOver18: true,
        country: "DE",
      },
      validUntilMs: 1_800_000_000_000,
    });

    const outcome = await verifier.verify({
      request: baseRequest,
      credential: baseCredential,
      submission: baseSubmission,
    });
    expect(outcome.result.status).toBe("REJECTED");
    expect(outcome.result.reasonCode).toBe("ISSUER_SIGNATURE_INVALID");
  });

  it("rejects when policy claims fail", async () => {
    const verifier = createVerifier({
      id: "sas_att_3",
      subjectWallet: "buyer_wallet_1",
      issuer: "trusted_issuer",
      schemaType: "KYC_VERIFIED",
      claims: {
        ageOver18: false,
        country: "US",
      },
      validUntilMs: 1_800_000_000_000,
    });

    const outcome = await verifier.verify({
      request: baseRequest,
      credential: baseCredential,
      submission: baseSubmission,
    });
    expect(outcome.result.status).toBe("REJECTED");
    expect(outcome.result.reasonCode).toBe("AGE_CHECK_FAILED");
  });
});

function createVerifier(attestation: SasAttestation | null): SasCredentialVerifier {
  return new SasCredentialVerifier({
    nowMs: () => 1_700_000_200_000,
    verificationWindowMs: 120_000,
    sasProvider: new InMemorySasProvider(attestation),
    policy: {
      trustedIssuers: new Set(["trusted_issuer"]),
      requiredSchemaType: "KYC_VERIFIED",
      requireAgeOver18: true,
      allowedCountries: new Set(["DE"]),
    },
  });
}

class InMemorySasProvider implements SasAttestationProvider {
  public constructor(private readonly attestation: SasAttestation | null) {}

  public async findLatestValidAttestation(subjectWallet: string): Promise<SasAttestation | null> {
    if (this.attestation === null) {
      return null;
    }
    if (this.attestation.subjectWallet !== subjectWallet) {
      return null;
    }
    return this.attestation;
  }
}
