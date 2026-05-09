import { createHash } from "node:crypto";
import express, { type Request, type Response } from "express";

const app = express();
const PORT = Number.parseInt(process.env.MOCK_SAS_PORT ?? "3100", 10);

app.get("/sas/attestations/latest", (req: Request, res: Response) => {
  const subject = String(req.query.subject ?? "");
  const negative = String(req.query.negative ?? "false").toLowerCase() === "true";
  if (subject.length === 0) {
    return res.status(400).json({ error: "subject query parameter is required" });
  }

  const now = Date.now();
  const issuedAt = now - 5 * 60 * 1000;
  const expiresAt = now + 24 * 60 * 60 * 1000;
  const attestationId = `sas_att_${subject}`;

  const attestation = {
    id: attestationId,
    subjectWallet: subject,
    issuer: negative ? "untrusted_issuer" : "shieldpay_sas_issuer_v1",
    schemaType: "KYC_VERIFIED",
    claims: {
      kycStatus: negative ? "REJECTED" : "VERIFIED",
      ageOver18: negative ? false : true,
      country: negative ? "US" : "DE",
    },
    revoked: false,
    validUntilMs: expiresAt,
  };

  const digest = createHash("sha256")
    .update(
      JSON.stringify({
        id: attestationId,
        subject,
        issuer: attestation.issuer,
        schemaType: attestation.schemaType,
        claims: attestation.claims,
        issuedAt,
        expiresAt,
      }),
    )
    .digest("hex");

  return res.json({
    attestation: {
      ...attestation,
      digestHex: digest,
      issuedAtMs: issuedAt,
      expiresAtMs: expiresAt,
    },
  });
});

app.listen(PORT, () => {
  console.log(`[mock-sas-service] running on http://127.0.0.1:${PORT}`);
});
