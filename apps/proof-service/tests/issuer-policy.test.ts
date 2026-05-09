import { describe, expect, it } from "vitest";

import type { CredentialEnvelope } from "@shieldpay/shared-types";
import { ShieldPaySingleIssuerPolicy } from "../src/index.js";

describe("ShieldPaySingleIssuerPolicy", () => {
  it("accepts only credentials from the configured ShieldPay issuer", () => {
    const policy = new ShieldPaySingleIssuerPolicy("shieldpay_issuer_v1");
    const credential: CredentialEnvelope = {
      credentialId: "cred_123",
      credentialType: "KYC_VERIFIED",
      subjectId: "subject_1",
      subjectPublicKeyHex: "ab".repeat(32),
      claims: {
        kycStatus: "VERIFIED",
        country: "DE",
        ageOver18: true,
      },
      issuerKeyId: "shieldpay_issuer_v1",
      issuedAtMs: 1_700_000_000_000,
      expiresAtMs: 1_800_000_000_000,
      issuerSignatureHex: "cd".repeat(64),
    };

    expect(policy.validateCredentialIssuer(credential)).toBe(true);
    expect(policy.validateCredentialIssuer({ ...credential, issuerKeyId: "rogue_issuer" })).toBe(false);
  });
});
