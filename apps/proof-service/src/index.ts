import { ed25519 } from "@noble/curves/ed25519";
import type {
  CredentialEnvelope,
  ProofVerificationResponse,
  ProofSubmission,
  SignedAttestation,
  VerificationRequest,
  VerificationResult,
  VerificationTrace,
} from "@shieldpay/shared-types";
import { computeAttestationDigestHex, verifyProofSubmission } from "@shieldpay/verification-core";

export type VerificationMode = "mock" | "sas";

export interface IssuerPolicy {
  validateCredentialIssuer(credential: CredentialEnvelope): boolean;
}

export class ShieldPaySingleIssuerPolicy implements IssuerPolicy {
  public constructor(private readonly shieldPayIssuerKeyId: string) {}

  public validateCredentialIssuer(credential: CredentialEnvelope): boolean {
    return credential.issuerKeyId === this.shieldPayIssuerKeyId;
  }
}

export interface ProofVerificationInput {
  request: VerificationRequest;
  credential: CredentialEnvelope;
  submission: ProofSubmission;
}

export interface ProofServiceDependencies {
  verifierKeyId: string;
  verifierPrivateKeyHex: string;
  nowMs: () => number;
  verificationWindowMs: number;
  credentialVerifier: CredentialVerifier;
}

export interface ProofServiceLegacyMockDependencies {
  issuerPolicy: IssuerPolicy;
  trustedIssuerPublicKeysByKeyId: Readonly<Record<string, string>>;
  verifierKeyId: string;
  verifierPrivateKeyHex: string;
  nowMs: () => number;
  verificationWindowMs: number;
  revokedCredentialIds: ReadonlySet<string>;
}

export interface CredentialVerifierInput {
  request: VerificationRequest;
  credential: CredentialEnvelope;
  submission: ProofSubmission;
}

export interface CredentialVerificationOutcome {
  result: VerificationResult;
  verificationTrace: VerificationTrace;
}

export interface CredentialVerifier {
  readonly mode: VerificationMode;
  verify(input: CredentialVerifierInput): Promise<CredentialVerificationOutcome>;
}

export class ProofService {
  public constructor(private readonly deps: ProofServiceDependencies | ProofServiceLegacyMockDependencies) {}

  public async verify(input: ProofVerificationInput): Promise<ProofVerificationResponse> {
    const credentialVerifier = this.resolveCredentialVerifier();
    console.log("[proof-service] selected verification mode", {
      mode: credentialVerifier.mode,
      requestId: input.request.requestId,
      buyerWallet: input.submission.subjectId,
    });
    const verification = await credentialVerifier.verify(input);

    console.log("[proof-service] credential verified", {
      requestId: input.request.requestId,
      buyerWallet: input.submission.subjectId,
      status: verification.result.status,
      reasonCode: verification.result.reasonCode,
    });
    return {
      ...signAttestation(verification.result, this.deps.verifierKeyId, this.deps.verifierPrivateKeyHex),
      verificationTrace: verification.verificationTrace,
    };
  }

  private resolveCredentialVerifier(): CredentialVerifier {
    if ("credentialVerifier" in this.deps) {
      return this.deps.credentialVerifier;
    }
    return new MockCredentialVerifier({
      issuerPolicy: this.deps.issuerPolicy,
      trustedIssuerPublicKeysByKeyId: this.deps.trustedIssuerPublicKeysByKeyId,
      nowMs: this.deps.nowMs,
      verificationWindowMs: this.deps.verificationWindowMs,
      revokedCredentialIds: this.deps.revokedCredentialIds,
    });
  }
}

export function signAttestation(
  result: VerificationResult,
  verifierKeyId: string,
  verifierPrivateKeyHex: string,
): SignedAttestation {
  const message = new TextEncoder().encode(
    [
      "shieldpay.attestation.v1",
      result.requestId,
      result.status,
      result.reasonCode,
      result.attestationDigestHex,
      String(result.decidedAtMs),
      verifierKeyId,
    ].join("|"),
  );

  const signatureHex = bytesToHex(ed25519.sign(message, hexToBytes(verifierPrivateKeyHex)));
  console.log("[proof-service] attestation signed", {
    requestId: result.requestId,
    verifierKeyId,
    status: result.status,
  });

  return {
    result,
    verifierKeyId,
    signatureHex,
  };
}

function buildVerificationTrace(
  input: ProofVerificationInput,
  result: VerificationResult,
  issuerTrusted: boolean,
): VerificationTrace {
  const credentialTypeValid = input.credential.credentialType === input.request.requiredCredentialType;
  const kycStatusValid = input.credential.claims.kycStatus === "VERIFIED";
  const ageCheckPassed = input.credential.claims.ageOver18 === true;
  const credentialNotExpired = input.credential.expiresAtMs >= result.decidedAtMs;
  const customerSignatureValid = result.reasonCode !== "SIGNATURE_INVALID";
  const issuerSignatureValid = issuerTrusted && result.reasonCode !== "ISSUER_SIGNATURE_INVALID";
  return {
    issuerTrusted,
    issuerSignatureValid,
    credentialNotExpired,
    credentialTypeValid,
    kycStatusValid,
    ageCheckPassed,
    customerSignatureValid,
    personalDataStoredOnChain: false,
    anchoredFields: ["requestPda", "status", "attestationDigest"],
  };
}

export interface MockCredentialVerifierDependencies {
  issuerPolicy: IssuerPolicy;
  trustedIssuerPublicKeysByKeyId: Readonly<Record<string, string>>;
  nowMs: () => number;
  verificationWindowMs: number;
  revokedCredentialIds: ReadonlySet<string>;
}

export class MockCredentialVerifier implements CredentialVerifier {
  public readonly mode = "mock";

  public constructor(private readonly deps: MockCredentialVerifierDependencies) {}

  public async verify(input: CredentialVerifierInput): Promise<CredentialVerificationOutcome> {
    const issuerTrusted = this.deps.issuerPolicy.validateCredentialIssuer(input.credential);
    const result: VerificationResult = issuerTrusted
      ? await verifyProofSubmission(
          {
            nowMs: this.deps.nowMs,
            verificationWindowMs: this.deps.verificationWindowMs,
            revokedCredentialIds: this.deps.revokedCredentialIds,
            trustedIssuerPublicKeysByKeyId: this.deps.trustedIssuerPublicKeysByKeyId,
          },
          input,
        )
      : buildRejectedResult(input, this.deps.verificationWindowMs, this.deps.nowMs(), "SIGNATURE_INVALID");
    return {
      result,
      verificationTrace: buildVerificationTrace(input, result, issuerTrusted),
    };
  }
}

export interface SasAttestation {
  id: string;
  subjectWallet: string;
  issuer: string;
  schemaType: string;
  claims: Partial<{
    ageOver18: boolean;
    country: string;
  }>;
  revoked?: boolean;
  validUntilMs?: number;
}

export interface SasAttestationProvider {
  findLatestValidAttestation(subjectWallet: string): Promise<SasAttestation | null>;
}

export class HttpSasAttestationProvider implements SasAttestationProvider {
  public constructor(private readonly endpoint: string) {}

  public async findLatestValidAttestation(subjectWallet: string): Promise<SasAttestation | null> {
    const response = await fetch(`${this.endpoint}?subject=${encodeURIComponent(subjectWallet)}`);
    if (!response.ok) {
      throw new Error(`SAS endpoint request failed with status ${response.status}`);
    }
    const payload = (await response.json()) as { attestation?: SasAttestation | null };
    return payload.attestation ?? null;
  }
}

export interface SasPolicy {
  trustedIssuers: ReadonlySet<string>;
  requiredSchemaType: string;
  requireAgeOver18: boolean;
  allowedCountries: ReadonlySet<string>;
}

export interface SasCredentialVerifierDependencies {
  nowMs: () => number;
  verificationWindowMs: number;
  sasProvider: SasAttestationProvider;
  policy: SasPolicy;
}

export class SasCredentialVerifier implements CredentialVerifier {
  public readonly mode = "sas";

  public constructor(private readonly deps: SasCredentialVerifierDependencies) {}

  public async verify(input: CredentialVerifierInput): Promise<CredentialVerificationOutcome> {
    const buyerWallet = input.submission.subjectId;
    const nowMs = this.deps.nowMs();
    const attestation = await this.deps.sasProvider.findLatestValidAttestation(buyerWallet);
    console.log("[proof-service] SAS attestation lookup", {
      requestId: input.request.requestId,
      buyerWallet,
      found: attestation !== null,
      attestationId: attestation?.id ?? null,
    });

    if (attestation === null) {
      return this.reject(input, nowMs, "SIGNATURE_INVALID", false, false, false, false, false);
    }

    const issuerTrusted = this.deps.policy.trustedIssuers.has(attestation.issuer);
    console.log("[proof-service] SAS trusted issuer check", {
      requestId: input.request.requestId,
      buyerWallet,
      issuer: attestation.issuer,
      issuerTrusted,
    });
    if (!issuerTrusted) {
      return this.reject(input, nowMs, "ISSUER_SIGNATURE_INVALID", issuerTrusted, false, false, false, false);
    }

    const schemaMatches = attestation.schemaType === this.deps.policy.requiredSchemaType;
    if (!schemaMatches) {
      return this.reject(input, nowMs, "CREDENTIAL_TYPE_MISMATCH", issuerTrusted, false, false, false, false);
    }

    if (attestation.subjectWallet !== buyerWallet) {
      return this.reject(input, nowMs, "SUBJECT_MISMATCH", issuerTrusted, false, false, false, false);
    }

    if (attestation.revoked === true) {
      return this.reject(input, nowMs, "CREDENTIAL_REVOKED", issuerTrusted, false, false, false, false);
    }

    if (attestation.validUntilMs !== undefined && attestation.validUntilMs < nowMs) {
      return this.reject(input, nowMs, "CREDENTIAL_EXPIRED", issuerTrusted, false, false, false, false);
    }

    const ageCheckPassed = this.deps.policy.requireAgeOver18 ? attestation.claims.ageOver18 === true : true;
    if (!ageCheckPassed) {
      return this.reject(input, nowMs, "AGE_CHECK_FAILED", issuerTrusted, true, true, ageCheckPassed, true);
    }

    const countryAllowed =
      this.deps.policy.allowedCountries.size === 0 ||
      (attestation.claims.country !== undefined && this.deps.policy.allowedCountries.has(attestation.claims.country));
    if (!countryAllowed) {
      return this.reject(input, nowMs, "KYC_NOT_VERIFIED", issuerTrusted, true, false, ageCheckPassed, true);
    }

    const result: VerificationResult = {
      requestId: input.request.requestId,
      subjectId: buyerWallet,
      status: "APPROVED",
      reasonCode: "OK",
      decidedAtMs: nowMs,
      verificationWindowMs: this.deps.verificationWindowMs,
      attestationDigestHex: "",
    };
    result.attestationDigestHex = computeAttestationDigestHex(result);
    console.log("[proof-service] SAS policy check", {
      requestId: input.request.requestId,
      buyerWallet,
      policyPassed: true,
      schemaType: attestation.schemaType,
      ageOver18: attestation.claims.ageOver18 ?? null,
      country: attestation.claims.country ?? null,
    });
    return {
      result,
      verificationTrace: {
        issuerTrusted,
        issuerSignatureValid: issuerTrusted,
        credentialNotExpired: true,
        credentialTypeValid: true,
        kycStatusValid: true,
        ageCheckPassed,
        customerSignatureValid: true,
        personalDataStoredOnChain: false,
        anchoredFields: ["requestPda", "status", "attestationDigest"],
      },
    };
  }

  private reject(
    input: CredentialVerifierInput,
    nowMs: number,
    reasonCode: VerificationResult["reasonCode"],
    issuerTrusted: boolean,
    credentialTypeValid: boolean,
    kycStatusValid: boolean,
    ageCheckPassed: boolean,
    credentialNotExpired: boolean,
  ): CredentialVerificationOutcome {
    const result = buildRejectedResult(input, this.deps.verificationWindowMs, nowMs, reasonCode);
    console.log("[proof-service] SAS policy check", {
      requestId: input.request.requestId,
      buyerWallet: input.submission.subjectId,
      policyPassed: false,
      reasonCode,
    });
    return {
      result,
      verificationTrace: {
        issuerTrusted,
        issuerSignatureValid: issuerTrusted,
        credentialNotExpired,
        credentialTypeValid,
        kycStatusValid,
        ageCheckPassed,
        customerSignatureValid: true,
        personalDataStoredOnChain: false,
        anchoredFields: ["requestPda", "status", "attestationDigest"],
      },
    };
  }
}

function buildRejectedResult(
  input: CredentialVerifierInput,
  verificationWindowMs: number,
  nowMs: number,
  reasonCode: VerificationResult["reasonCode"],
): VerificationResult {
  const result: VerificationResult = {
    requestId: input.request.requestId,
    subjectId: input.submission.subjectId,
    status: "REJECTED",
    reasonCode,
    decidedAtMs: nowMs,
    verificationWindowMs,
    attestationDigestHex: "",
  };
  result.attestationDigestHex = computeAttestationDigestHex(result);
  return result;
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
