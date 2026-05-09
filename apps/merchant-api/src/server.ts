import cors from "cors";
import express, { type Request, type Response } from "express";
import { Keypair, PublicKey } from "@solana/web3.js";
import {
  HttpSasAttestationProvider,
  MockCredentialVerifier,
  ProofService,
  SasCredentialVerifier,
  type CredentialVerifier,
  ShieldPaySingleIssuerPolicy,
  type VerificationMode,
} from "@shieldpay/proof-service";
import type { CredentialEnvelope, ProofSubmission } from "@shieldpay/shared-types";
import { deriveRequestPda, requestIdSeed16FromString } from "@shieldpay/solana-gatekeeper-sdk";
import {
  getDemoIssuerPublicKeyHex,
  MerchantSolanaAnchoringClient,
  MerchantVerificationService,
  type MerchantCreateRequestInput,
} from "./index.js";

const PORT = Number.parseInt(process.env.MERCHANT_API_PORT ?? "3000", 10);
const SHIELDPAY_ISSUER_KEY_ID = process.env.SHIELDPAY_ISSUER_KEY_ID ?? "shieldpay_issuer_v1";
const VERIFIER_KEY_ID = process.env.VERIFIER_KEY_ID ?? "verifier_global_v1";
const VERIFIER_PRIVATE_KEY_HEX = process.env.VERIFIER_PRIVATE_KEY_HEX ?? "34".repeat(32);
const VERIFICATION_MODE = parseVerificationMode(process.env.VERIFICATION_MODE);
const SAS_ATTESTATION_ENDPOINT =
  process.env.SAS_ATTESTATION_ENDPOINT ?? "http://127.0.0.1:3100/sas/attestations/latest";
const SAS_TRUSTED_ISSUERS = toSet(process.env.SAS_TRUSTED_ISSUERS ?? "shieldpay_sas_issuer_v1");
const SAS_REQUIRED_SCHEMA = process.env.SAS_REQUIRED_SCHEMA ?? "KYC_VERIFIED";
const SAS_REQUIRE_AGE_OVER_18 = (process.env.SAS_REQUIRE_AGE_OVER_18 ?? "true").toLowerCase() !== "false";
const SAS_ALLOWED_COUNTRIES = toSet(process.env.SAS_ALLOWED_COUNTRIES ?? "DE");

const merchantSigner = Keypair.fromSeed(new Uint8Array(32).fill(7));
const verifierSigner = Keypair.fromSeed(new Uint8Array(32).fill(9));
const anchoringClient = new MerchantSolanaAnchoringClient(
  process.env.SOLANA_RPC_URL === undefined
    ? {
        cluster: (process.env.SOLANA_CLUSTER as "localnet" | "devnet" | undefined) ?? "localnet",
        merchantSigner,
        verifierSigner,
      }
    : {
        cluster: (process.env.SOLANA_CLUSTER as "localnet" | "devnet" | undefined) ?? "localnet",
        rpcUrl: process.env.SOLANA_RPC_URL,
        merchantSigner,
        verifierSigner,
      },
);

const credentialVerifier = buildCredentialVerifier(VERIFICATION_MODE);
console.log("[merchant-api] selected verification mode", { mode: VERIFICATION_MODE });
const proofService = new ProofService({
  credentialVerifier,
  verifierKeyId: VERIFIER_KEY_ID,
  verifierPrivateKeyHex: VERIFIER_PRIVATE_KEY_HEX,
  nowMs: () => Date.now(),
  verificationWindowMs: 120_000,
  revokedCredentialIds: new Set<string>(),
});
const merchantService = new MerchantVerificationService(proofService, () => Date.now(), anchoringClient);

const app = express();
app.use(cors());
app.use(express.json());

const defaultRequestInput: MerchantCreateRequestInput = {
  merchantId: "merchant_demo_1",
  merchantWallet: merchantSigner.publicKey.toBase58(),
  requiredCredentialType: "KYC_VERIFIED",
  ttlMs: 5 * 60 * 1000,
};

app.post("/requests", async (req: Request, res: Response) => {
  try {
    const body = req.body as Partial<MerchantCreateRequestInput> | undefined;
    const request = await merchantService.createVerificationRequest({
      ...defaultRequestInput,
      ...body,
      merchantWallet: defaultRequestInput.merchantWallet,
    });
    const requestPda = deriveRequestPda(
      new PublicKey(request.merchantWallet),
      requestIdSeed16FromString(request.requestId),
    ).toBase58();
    console.log("[merchant-api] request created", { requestId: request.requestId });
    res.status(201).json({ ...request, requestPda });
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

app.get("/requests/:requestId/status", (req: Request, res: Response) => {
  const requestId = req.params.requestId;
  if (typeof requestId !== "string") {
    return res.status(400).json({ error: "invalid requestId" });
  }
  const status = merchantService.getVerificationStatus(requestId);
  console.log("[merchant-api] final status read from API", {
    requestId,
    status: status?.status ?? null,
  });
  if (status === null) {
    return res.status(404).json({ error: "request not found" });
  }
  return res.json(status);
});

app.get("/requests/:requestId/anchored-status", async (req: Request, res: Response) => {
  const requestId = req.params.requestId;
  if (typeof requestId !== "string") {
    return res.status(400).json({ error: "invalid requestId" });
  }
  try {
    const status = await merchantService.getAnchoredVerificationStatus(requestId);
    if (status === null) {
      return res.status(404).json({ error: "request not found or not anchored" });
    }
    return res.json({ requestId, status });
  } catch (error) {
    return res.status(500).json({ error: (error as Error).message });
  }
});

app.post("/requests/:requestId/proof", async (req: Request, res: Response) => {
  const requestId = req.params.requestId;
  if (typeof requestId !== "string") {
    return res.status(400).json({ error: "invalid requestId" });
  }
  try {
    const body = req.body as {
      credential: CredentialEnvelope;
      submission: ProofSubmission;
    };
    console.log("[merchant-api] proof submitted", { requestId });
    const { attestation, transactionSignature } = await merchantService.submitProof(
      requestId,
      body.credential,
      body.submission,
    );
    const request = merchantService.getRequest(requestId);
    if (request === null) {
      return res.status(404).json({ error: "request not found" });
    }
    const requestPda = deriveRequestPda(
      new PublicKey(request.merchantWallet),
      requestIdSeed16FromString(requestId),
    ).toBase58();
    return res.json({
      ...attestation,
      verificationTrace: attestation.verificationTrace,
      demoMetadata: {
        credentialType: body.credential.credentialType,
        issuerKeyId: body.credential.issuerKeyId,
        subjectId: body.credential.subjectId,
        issuedAtMs: body.credential.issuedAtMs,
        expiresAtMs: body.credential.expiresAtMs,
        subjectPublicKeyHex: shortenForDisplay(body.credential.subjectPublicKeyHex),
        issuerSignatureHex: shortenForDisplay(body.credential.issuerSignatureHex),
        challengeMessage: shortenForDisplay(body.submission.challenge),
        customerSignatureHex: shortenForDisplay(body.submission.signatureHex),
        attestationDigest: attestation.result.attestationDigestHex,
        requestPda,
        transactionSignature,
      },
    });
  } catch (error) {
    return res.status(400).json({ error: (error as Error).message });
  }
});

function buildCredentialVerifier(mode: VerificationMode): CredentialVerifier {
  if (mode === "sas") {
    return new SasCredentialVerifier({
      nowMs: () => Date.now(),
      verificationWindowMs: 120_000,
      sasProvider: new HttpSasAttestationProvider(SAS_ATTESTATION_ENDPOINT),
      policy: {
        trustedIssuers: SAS_TRUSTED_ISSUERS,
        requiredSchemaType: SAS_REQUIRED_SCHEMA,
        requireAgeOver18: SAS_REQUIRE_AGE_OVER_18,
        allowedCountries: SAS_ALLOWED_COUNTRIES,
      },
    });
  }
  return new MockCredentialVerifier({
    issuerPolicy: new ShieldPaySingleIssuerPolicy(SHIELDPAY_ISSUER_KEY_ID),
    trustedIssuerPublicKeysByKeyId: {
      [SHIELDPAY_ISSUER_KEY_ID]: getDemoIssuerPublicKeyHex(),
    },
    nowMs: () => Date.now(),
    verificationWindowMs: 120_000,
    revokedCredentialIds: new Set<string>(),
  });
}

function parseVerificationMode(raw: string | undefined): VerificationMode {
  if (raw === "sas") {
    return "sas";
  }
  return "mock";
}

function toSet(rawCsv: string): ReadonlySet<string> {
  return new Set(
    rawCsv
      .split(",")
      .map((value) => value.trim())
      .filter((value) => value.length > 0),
  );
}

function shortenForDisplay(value: string): string {
  if (value.length <= 20) {
    return value;
  }
  return `${value.slice(0, 8)}...${value.slice(-8)}`;
}

anchoringClient
  .ensureReady()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`[merchant-api] running on http://127.0.0.1:${PORT}`);
    });
  })
  .catch((error) => {
    console.error("[merchant-api] failed to initialize", error);
    process.exit(1);
  });
