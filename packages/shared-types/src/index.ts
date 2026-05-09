export type VerificationStatus = "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";

export interface VerificationRequest {
  requestId: string;
  merchantId: string;
  merchantWallet: string;
  challenge: string;
  createdAtMs: number;
  expiresAtMs: number;
  requiredCredentialType: "KYC_VERIFIED";
}

export interface CredentialEnvelope {
  credentialId: string;
  credentialType: "KYC_VERIFIED";
  subjectId: string;
  subjectPublicKeyHex: string;
  claims: {
    kycStatus: "VERIFIED";
    country: "DE";
    ageOver18: true;
  };
  issuerKeyId: string;
  issuedAtMs: number;
  expiresAtMs: number;
  issuerSignatureHex: string;
}

export interface ProofSubmission {
  requestId: string;
  credentialId: string;
  subjectId: string;
  challenge: string;
  signedAtMs: number;
  signatureHex: string;
}

export interface VerificationResult {
  requestId: string;
  subjectId: string;
  status: VerificationStatus;
  reasonCode:
    | "OK"
    | "REQUEST_NOT_FOUND"
    | "REQUEST_EXPIRED"
    | "CHALLENGE_MISMATCH"
    | "CREDENTIAL_EXPIRED"
    | "CREDENTIAL_REVOKED"
    | "CREDENTIAL_TYPE_MISMATCH"
    | "KYC_NOT_VERIFIED"
    | "AGE_CHECK_FAILED"
    | "SUBJECT_MISMATCH"
    | "ISSUER_SIGNATURE_INVALID"
    | "SIGNATURE_INVALID"
    | "SUBMISSION_STALE";
  decidedAtMs: number;
  verificationWindowMs: number;
  attestationDigestHex: string;
}

export interface SignedAttestation {
  result: VerificationResult;
  verifierKeyId: string;
  signatureHex: string;
}

export interface VerificationTrace {
  issuerTrusted: boolean;
  issuerSignatureValid: boolean;
  credentialNotExpired: boolean;
  credentialTypeValid: boolean;
  kycStatusValid: boolean;
  ageCheckPassed: boolean;
  customerSignatureValid: boolean;
  personalDataStoredOnChain: false;
  anchoredFields: ["requestPda", "status", "attestationDigest"];
}

export interface ProofVerificationResponse extends SignedAttestation {
  verificationTrace: VerificationTrace;
}

export interface VerificationStatusView {
  requestId: string;
  merchantId: string;
  status: VerificationStatus;
  attestationDigestHex: string | null;
  verifierKeyId: string | null;
  updatedAtMs: number;
}
