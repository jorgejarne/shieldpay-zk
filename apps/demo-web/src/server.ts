import express, { type Request, type Response } from "express";
import {
  createMockCredentialEnvelope,
  generateDemoCustomerIdentity,
  signProofForRequest,
  type DemoCustomerIdentity,
} from "@shieldpay/merchant-api";
import type { VerificationRequest } from "@shieldpay/shared-types";

const app = express();
app.use(express.json());

const PORT = Number.parseInt(process.env.DEMO_WEB_PORT ?? "4173", 10);
const merchantApiBaseUrl = process.env.MERCHANT_API_BASE_URL ?? "http://127.0.0.1:3000";
const mockSasBaseUrl = process.env.MOCK_SAS_BASE_URL ?? "http://127.0.0.1:3100";
const verificationMode = process.env.VERIFICATION_MODE === "sas" ? "sas" : "mock";
const issuerKeyId = process.env.SHIELDPAY_ISSUER_KEY_ID ?? "shieldpay_issuer_v1";
const solanaCluster =
  (process.env.SOLANA_CLUSTER as "localnet" | "devnet" | undefined) === "devnet" ? "devnet" : "localnet";
const solanaRpcUrl = process.env.SOLANA_RPC_URL ?? "http://localhost:8899";

let customerIdentity: DemoCustomerIdentity = generateDemoCustomerIdentity("buyer_demo_1");
let storedCredential: ReturnType<typeof createMockCredentialEnvelope> | null = null;

/** Mirrors “wallet” negative SAS demo; merged into ShieldPay lookup via {@link resolveSasNegativeForVerifier}. */
const sasDemoNegativeSubjects = new Set<string>();

function resolveSasNegativeForVerifier(req: Request, subject: string): boolean {
  const raw = typeof req.query.negative === "string" ? req.query.negative.toLowerCase() : undefined;
  if (raw === "true") return true;
  if (raw === "false") return false;
  return sasDemoNegativeSubjects.has(subject);
}

async function fetchMockSasLatestJson(subject: string, negative: boolean): Promise<{ status: number; payload: unknown }> {
  const url = `${mockSasBaseUrl}/sas/attestations/latest?subject=${encodeURIComponent(subject)}&negative=${negative ? "true" : "false"}`;
  const response = await fetch(url);
  const body = await response.text();
  try {
    const payload = JSON.parse(body) as unknown;
    return { status: response.status, payload };
  } catch {
    return {
      status: 502,
      payload: {
        error: `Mock SAS at ${mockSasBaseUrl} did not return JSON. Start it with: npm run dev:mock-sas-service`,
        detail: body.slice(0, 240),
      },
    };
  }
}

/** Mock SAS may omit kycStatus on older builds; keep UI and recordings aligned with policy. */
function ensureMockSasKycClaims(payload: unknown, negativeEffective: boolean): void {
  if (!payload || typeof payload !== "object") return;
  const attestation = (payload as { attestation?: unknown }).attestation;
  if (!attestation || typeof attestation !== "object") return;
  const row = attestation as { claims?: unknown };
  if (!row.claims || typeof row.claims !== "object") {
    row.claims = {};
  }
  const claims = row.claims as Record<string, unknown>;
  const existing = claims.kycStatus;
  if (
    existing === undefined ||
    existing === null ||
    (typeof existing === "string" && existing.trim().length === 0)
  ) {
    claims.kycStatus = negativeEffective ? "REJECTED" : "VERIFIED";
  }
}

app.get("/", (_req: Request, res: Response) => {
  res.type("html").send(renderHtml());
});

app.get("/api/customer", (_req: Request, res: Response) => {
  res.json({
    subjectId: customerIdentity.subjectId,
    buyerWallet: customerIdentity.publicKeyHex,
    publicKeyHex: customerIdentity.publicKeyHex,
  });
});

app.get("/api/config", (_req: Request, res: Response) => {
  res.json({
    verificationMode,
    merchantApiBaseUrl,
    solanaCluster,
    solanaRpcUrl,
  });
});

app.post("/api/merchant/request", async (_req: Request, res: Response) => {
  const response = await fetch(`${merchantApiBaseUrl}/requests`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({}),
  });
  const payload = await response.json();
  res.status(response.status).json(payload);
});

app.post("/api/buyer/issue-credential", (_req: Request, res: Response) => {
  storedCredential = createMockCredentialEnvelope(customerIdentity, issuerKeyId, Date.now());
  return res.json({
    credential: storedCredential,
    storage: "off-chain",
  });
});

app.get("/api/merchant/:requestId/status", async (req: Request, res: Response) => {
  const response = await fetch(`${merchantApiBaseUrl}/requests/${req.params.requestId}/status`);
  const payload = await response.json();
  res.status(response.status).json(payload);
});

app.get("/api/merchant/:requestId/anchored-status", async (req: Request, res: Response) => {
  const response = await fetch(`${merchantApiBaseUrl}/requests/${req.params.requestId}/anchored-status`);
  const payload = await response.json();
  res.status(response.status).json(payload);
});

app.post("/api/buyer/submit", async (req: Request, res: Response) => {
  const request = req.body.request as VerificationRequest | undefined;
  if (request === undefined) {
    return res.status(400).json({ error: "request is required" });
  }
  if (storedCredential === null && verificationMode === "mock") {
    return res.status(400).json({ error: "issue credential first" });
  }
  if (storedCredential === null) {
    storedCredential = createMockCredentialEnvelope(customerIdentity, issuerKeyId, Date.now());
  }
  const credentialForSubmission = {
    ...storedCredential,
    subjectId: customerIdentity.publicKeyHex,
  };
  const submission = signProofForRequest(request, credentialForSubmission, customerIdentity, Date.now());

  const response = await fetch(`${merchantApiBaseUrl}/requests/${request.requestId}/proof`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ credential: credentialForSubmission, submission }),
  });
  const payload = await response.json();
  return res.status(response.status).json(payload);
});

app.get("/api/sas/attestation", async (req: Request, res: Response) => {
  const subject = String(req.query.subject ?? "").trim();
  const negative = String(req.query.negative ?? "false").toLowerCase() === "true";
  if (subject.length === 0) {
    return res.status(400).json({ error: "subject is required" });
  }
  try {
    if (negative) {
      sasDemoNegativeSubjects.add(subject);
    } else {
      sasDemoNegativeSubjects.delete(subject);
    }
    const { status, payload } = await fetchMockSasLatestJson(subject, negative);
    if (status >= 200 && status < 300) {
      ensureMockSasKycClaims(payload, negative);
    }
    return res.status(status).json(payload);
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    console.error("[demo-web] SAS attestation fetch failed", { message, mockSasBaseUrl });
    return res.status(502).json({ error: "failed to reach mock SAS", detail: message });
  }
});

/**
 * ShieldPay SAS lookup URL for local demo: same JSON as mock-sas, but merges {@link sasDemoNegativeSubjects}
 * when `negative` is omitted (merchant-api only passes `?subject=`).
 */
app.get("/api/sas/attestations/latest", async (req: Request, res: Response) => {
  const subjectTrimmed = String(req.query.subject ?? "").trim();
  if (subjectTrimmed.length === 0) {
    return res.status(400).json({ error: "subject query parameter is required" });
  }
  const negative = resolveSasNegativeForVerifier(req, subjectTrimmed);
  try {
    const { status, payload } = await fetchMockSasLatestJson(subjectTrimmed, negative);
    if (status >= 200 && status < 300) {
      ensureMockSasKycClaims(payload, negative);
    }
    return res.status(status).json(payload);
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : String(cause);
    console.error("[demo-web] SAS verifier proxy failed", { message, mockSasBaseUrl });
    return res.status(502).json({ error: "failed to reach mock SAS", detail: message });
  }
});

app.listen(PORT, () => {
  console.log(`[demo-web] running on http://127.0.0.1:${PORT}`);
  console.log(
    `[demo-web] SAS verifier proxy — set merchant-api SAS_ATTESTATION_ENDPOINT=http://127.0.0.1:${PORT}/api/sas/attestations/latest when using VERIFICATION_MODE=sas`,
  );
});

function renderHtml(): string {
  return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>ShieldPay Verification Demo</title>
    <style>
      * { box-sizing: border-box; }
      body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; margin: 0; background: linear-gradient(180deg, #f0f4f8 0%, #e8eef5 100%); color: #0f172a; min-height: 100vh; }
      .container { max-width: 1120px; margin: 0 auto; padding: 24px 20px 48px; }
      .intro { margin: 0 0 20px 0; color: #475569; font-size: 15px; line-height: 1.5; }
      .tabs { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
      .tab-btn { border: 1px solid #e2e8f0; background: #fff; color: #334155; border-radius: 10px; padding: 10px 16px; font-weight: 600; font-size: 14px; cursor: pointer; box-shadow: 0 1px 2px rgba(15,23,42,0.06); }
      .tab-btn.active { background: #1d4ed8; color: #fff; border-color: #1d4ed8; box-shadow: 0 2px 8px rgba(29,78,216,0.25); }
      .tab-panel { display: none; }
      .tab-panel.active { display: block; }
      .technical-debug-note { font-size: 13px; color: #64748b; margin: -8px 0 14px 0; }
      .card { border: 1px solid #e2e8f0; border-radius: 16px; padding: 18px 20px; background: #fff; margin-bottom: 14px; box-shadow: 0 1px 3px rgba(15,23,42,0.06); }
      .card h2 { margin: 0 0 10px 0; font-size: 18px; font-weight: 700; letter-spacing: -0.02em; }
      .card h3 { margin: 0 0 10px 0; font-size: 15px; font-weight: 700; }
      .story-note { margin: 0 0 10px 0; color: #475569; font-size: 14px; line-height: 1.45; }
      .flow { display: grid; grid-template-columns: 1fr; gap: 12px; }
      .row { display: grid; grid-template-columns: minmax(140px, 200px) 1fr; gap: 10px 14px; margin: 6px 0; align-items: start; font-size: 13px; }
      .label { color: #64748b; font-weight: 600; }
      .value { color: #0f172a; word-break: break-word; }
      .muted { color: #94a3b8; }
      .actions { margin-top: 12px; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
      button { margin: 0; border: none; border-radius: 10px; padding: 12px 20px; background: #1d4ed8; color: #fff; cursor: pointer; font-weight: 600; font-size: 14px; box-shadow: 0 2px 6px rgba(29,78,216,0.2); transition: transform 0.05s, box-shadow 0.15s; }
      button:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(29,78,216,0.28); }
      button:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
      button.secondary { background: #0f766e; box-shadow: 0 2px 6px rgba(15,118,110,0.2); }
      button.warning { background: #7c3aed; box-shadow: 0 2px 6px rgba(124,58,237,0.2); }
      button.cta-outline { background: #fff; color: #1d4ed8; border: 2px solid #1d4ed8; box-shadow: none; }
      .badge { display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 700; letter-spacing: 0.03em; text-transform: uppercase; }
      .mode { background: #dbeafe; color: #1e40af; }
      .pending { background: #fef3c7; color: #b45309; }
      .approved { background: #dcfce7; color: #166534; }
      .rejected { background: #fee2e2; color: #b91c1c; }
      .status { display: inline-flex; padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 700; background: #f1f5f9; color: #475569; text-transform: uppercase; }
      .logs { max-height: 220px; overflow-y: auto; background: #0b1020; color: #e5e7eb; border-radius: 12px; padding: 12px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; white-space: pre-wrap; }
      .checkout-grid { display: grid; grid-template-columns: 1fr; gap: 20px; }
      @media (min-width: 900px) {
        .checkout-grid { grid-template-columns: 1.15fr 0.85fr; align-items: start; }
      }
      .product-card { display: flex; flex-direction: column; gap: 16px; overflow: hidden; }
      @media (min-width: 520px) {
        .product-card { flex-direction: row; align-items: stretch; }
      }
      .product-img-wrap { flex-shrink: 0; border-radius: 14px; overflow: hidden; background: #f1f5f9; border: 1px solid #e2e8f0; width: 100%; max-width: 260px; aspect-ratio: 4/3; }
      .product-img-wrap img { width: 100%; height: 100%; object-fit: cover; display: block; }
      .product-body { flex: 1; min-width: 0; }
      .product-title { font-size: 22px; font-weight: 700; letter-spacing: -0.03em; margin: 0 0 6px 0; }
      .product-price { font-size: 26px; font-weight: 800; color: #0f172a; margin: 0 0 8px 0; }
      .meta-line { font-size: 13px; color: #64748b; margin: 4px 0; }
      .risk-badges { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
      .risk-badges .badge-danger { background: #fef2f2; color: #b91c1c; }
      .risk-badges .badge-warn { background: #fff7ed; color: #c2410c; }
      .checkout-side { display: flex; flex-direction: column; gap: 14px; }
      .summary-row { display: flex; justify-content: space-between; font-size: 14px; padding: 8px 0; border-bottom: 1px solid #f1f5f9; }
      .summary-row.total { font-weight: 700; font-size: 17px; border-bottom: none; padding-top: 12px; }
      .verification-panel { border: 1px dashed #cbd5e1; border-radius: 14px; padding: 16px; background: #fafbfc; }
      .verify-hint { font-size: 13px; color: #64748b; margin-top: 10px; min-height: 1.2em; }
      .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid #e2e8f0; border-top-color: #1d4ed8; border-radius: 50%; animation: sp 0.7s linear infinite; vertical-align: middle; margin-right: 8px; }
      @keyframes sp { to { transform: rotate(360deg); } }
      .merchant-decision { border-radius: 14px; padding: 18px; border: 1px solid #e2e8f0; }
      .merchant-decision.pending { background: #fafafa; }
      .merchant-decision.ok { background: #f0fdf4; border-color: #bbf7d0; }
      .merchant-decision.bad { background: #fef2f2; border-color: #fecaca; }
      .decision-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }
      .decision-msg { font-size: 15px; font-weight: 600; margin: 0 0 8px 0; }
      .decision-note { font-size: 13px; color: #64748b; margin: 0 0 12px 0; }
      .decision-meta { font-size: 12px; color: #475569; line-height: 1.6; }
      .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(15,23,42,0.45); backdrop-filter: blur(6px); z-index: 1000; align-items: center; justify-content: center; padding: 20px; }
      .modal-overlay.open { display: flex; }
      .modal-sheet { width: 100%; max-width: 420px; background: #fff; border-radius: 20px; box-shadow: 0 25px 50px -12px rgba(15,23,42,0.35); overflow: hidden; border: 1px solid rgba(255,255,255,0.8); }
      .modal-header { padding: 20px 22px 12px; text-align: center; border-bottom: 1px solid #f1f5f9; background: linear-gradient(180deg, #fafbfc 0%, #fff 100%); }
      .modal-logo { width: 48px; height: 48px; margin: 0 auto 10px; border-radius: 14px; background: linear-gradient(135deg, #1d4ed8, #6366f1); display: flex; align-items: center; justify-content: center; color: #fff; font-weight: 800; font-size: 18px; }
      .modal-title { margin: 0; font-size: 17px; font-weight: 700; letter-spacing: -0.02em; }
      .modal-sub { margin: 6px 0 0; font-size: 13px; color: #64748b; }
      .modal-body { padding: 18px 22px 22px; max-height: min(70vh, 560px); overflow-y: auto; }
      .modal-merchant { text-align: center; font-weight: 600; font-size: 15px; margin-bottom: 14px; }
      .wallet-pill { display: inline-block; font-size: 12px; font-family: ui-monospace, monospace; background: #f1f5f9; padding: 6px 12px; border-radius: 999px; color: #334155; word-break: break-all; max-width: 100%; }
      .policy-list { margin: 14px 0; padding: 12px 14px; background: #f8fafc; border-radius: 12px; font-size: 13px; border: 1px solid #e2e8f0; }
      .policy-list strong { display: block; margin-bottom: 6px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: #64748b; }
      .policy-list ul { margin: 0; padding-left: 18px; color: #334155; }
      .share-columns { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 12px; }
      @media (max-width: 400px) { .share-columns { grid-template-columns: 1fr; } }
      .share-col { padding: 10px 12px; border-radius: 12px; border: 1px solid #e2e8f0; background: #fff; }
      .share-col.yes { border-color: #bbf7d0; background: #f0fdf4; }
      .share-col.no { border-color: #fecaca; background: #fef2f2; }
      .share-col ul { margin: 6px 0 0; padding-left: 16px; }
      .modal-status { margin-top: 14px; font-size: 13px; color: #475569; text-align: center; min-height: 1.5em; }
      .modal-success { color: #166534; font-weight: 600; text-align: center; margin-top: 10px; font-size: 13px; display: none; }
      .modal-success.visible { display: block; }
      .modal-actions { padding: 0 22px 22px; display: flex; flex-direction: column; gap: 10px; }
      .modal-actions button { width: 100%; margin: 0; border-radius: 12px; padding: 14px; font-size: 15px; }
      .solana-step-header { display: flex; flex-wrap: wrap; align-items: center; gap: 10px 14px; margin-bottom: 4px; }
      .solana-step-header h3 { margin: 0; flex: 1 1 auto; min-width: 200px; }
      .badge.solana-anchored { background: linear-gradient(135deg, #dcfce7 0%, #d1fae5 100%); color: #047857; border: 1px solid #a7f3d0; text-transform: none; letter-spacing: 0.01em; font-size: 12px; font-weight: 700; }
      .tx-sig-row { display: flex; flex-wrap: wrap; align-items: center; gap: 10px 14px; }
      code.tx-sig { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 13px; font-weight: 500; letter-spacing: 0.02em; line-height: 1.5; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px; padding: 10px 12px; color: #0f172a; word-break: break-all; max-width: 100%; }
      a.explorer-link { display: inline-flex; align-items: center; font-size: 13px; font-weight: 600; color: #1d4ed8; text-decoration: none; border-radius: 8px; padding: 8px 12px; border: 1px solid #bfdbfe; background: #eff6ff; }
      a.explorer-link:hover { background: #dbeafe; border-color: #93c5fd; }
      .privacy-callout { font-size: 13px; color: #475569; line-height: 1.55; margin: 0; padding: 12px 14px; background: #f8fafc; border-radius: 12px; border-left: 4px solid #94a3b8; }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>ShieldPay Verification Demo</h1>
      <p class="intro"><strong>ShieldPay verifies buyer attestations off-chain and anchors APPROVED/REJECTED results on Solana.</strong></p>

      <div class="tabs">
        <button class="tab-btn active" data-tab="checkout">Merchant Checkout</button>
        <button class="tab-btn" data-tab="issuer">Issuer / SAS</button>
        <button class="tab-btn" data-tab="technical">Technical Flow</button>
      </div>

      <section id="tab-checkout" class="tab-panel active">
        <div class="checkout-grid">
          <div class="card product-card">
            <div class="product-img-wrap">
              <img src="https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=520&h=390&fit=crop" alt="MacBook Pro" width="260" height="195" />
            </div>
            <div class="product-body">
              <h2 class="product-title">MacBook Pro 16"</h2>
              <p class="product-price">€2,499</p>
              <p class="meta-line"><strong>Merchant</strong> · TechStore Berlin</p>
              <p class="meta-line"><strong>Category</strong> · High-risk electronics order</p>
              <p class="meta-line"><strong>Quantity</strong> · 1</p>
              <p class="meta-line"><strong>Shipping</strong> · Express delivery · Estimated 2–4 business days</p>
              <p class="meta-line" style="margin-top:10px;color:#475569;">New buyer with no previous merchant trust history.</p>
              <div class="risk-badges">
                <span class="badge badge-danger">Fraud risk: HIGH</span>
                <span class="badge badge-warn">Verification required before payment</span>
              </div>
            </div>
          </div>
          <div class="checkout-side">
            <div class="card">
              <h2>Order summary</h2>
              <div class="summary-row"><span>MacBook Pro 16" × 1</span><span>€2,499</span></div>
              <div class="summary-row"><span>Shipping</span><span>€0</span></div>
              <div class="summary-row total"><span>Total</span><span>€2,499</span></div>
            </div>
            <div class="card verification-panel">
              <h2 style="margin-bottom:4px;">Buyer verification</h2>
              <p class="story-note" style="margin-bottom:12px;">ShieldPay verifies the buyer wallet before this order can be paid.</p>
              <div class="row" style="grid-template-columns: 120px 1fr;"><span class="label">Buyer wallet</span><span id="checkoutBuyerWallet" class="value muted" style="font-family: ui-monospace, monospace; font-size: 12px;">Loading...</span></div>
              <div class="actions" style="margin-top:14px;">
                <button id="verifyBuyer">Verify buyer with ShieldPay</button>
              </div>
              <div id="verifyLoadingHint" class="verify-hint"></div>
            </div>
            <div id="merchantDecisionCard" class="merchant-decision pending">
              <h3 style="margin:0 0 12px;font-size:15px;font-weight:700;">Merchant decision</h3>
              <div class="decision-head">
                <span id="decisionBadge" class="badge pending" style="display:none;"></span>
              </div>
              <p id="checkoutDecisionTitle" class="decision-msg">Waiting for verification</p>
              <p id="checkoutDecisionNote" class="decision-note" style="display:none;"></p>
              <div id="checkoutDecisionMeta" class="decision-meta" style="display:none;"></div>
              <div class="actions" style="margin-top:14px;margin-bottom:0;">
                <button id="continuePayment" class="secondary" style="display: none;">Continue to payment</button>
              </div>
            </div>
          </div>
        </div>
      </section>

      <div id="shieldpayModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="shieldpayModalTitle">
        <div class="modal-sheet">
          <div class="modal-header">
            <div class="modal-logo">S</div>
            <h2 id="shieldpayModalTitle" class="modal-title">ShieldPay Verification Request</h2>
            <p class="modal-sub">Confirm identity checks without sharing raw personal data</p>
          </div>
          <div class="modal-body">
            <div class="modal-merchant">Merchant: TechStore Berlin</div>
            <div style="text-align:center;"><span id="modalBuyerWallet" class="wallet-pill">—</span></div>
            <div class="policy-list">
              <strong>Requested policy</strong>
              <ul style="margin:0;padding-left:18px;">
                <li>KYC_VERIFIED</li>
                <li>ageOver18 = true</li>
                <li>country = DE</li>
              </ul>
            </div>
            <div class="share-columns">
              <div class="share-col yes">
                <strong style="font-size:11px;text-transform:uppercase;color:#166534;">Data shared</strong>
                <ul>
                  <li>verification result</li>
                  <li>attestation digest</li>
                  <li>buyer wallet signature</li>
                </ul>
              </div>
              <div class="share-col no">
                <strong style="font-size:11px;text-transform:uppercase;color:#b91c1c;">Data NOT shared</strong>
                <ul>
                  <li>full identity</li>
                  <li>address</li>
                  <li>passport / ID</li>
                  <li>date of birth</li>
                </ul>
              </div>
            </div>
            <div id="modalSignSuccess" class="modal-success">Challenge signed successfully</div>
            <div id="modalProgress" class="modal-status"></div>
          </div>
          <div class="modal-actions">
            <button type="button" id="modalSignRequest" class="secondary">Sign Verification Request</button>
            <button type="button" id="modalSubmitProof" class="warning" disabled>Submit Proof</button>
          </div>
        </div>
      </div>

      <section id="tab-issuer" class="tab-panel">
        <div class="card">
          <h2 id="issuerTitle">Issuer</h2>
          <p id="issuerDescription" class="story-note"></p>
          <div class="actions">
            <button id="issue">Issue mock credential</button>
            <button id="issueNegativeMock" class="warning">Issue negative mock credential</button>
            <button id="loadSas" class="secondary">Load SAS attestation</button>
            <button id="loadSasNegative" class="warning">Load negative SAS attestation</button>
          </div>
        </div>
        <div class="card">
          <h3>Buyer Wallet</h3>
          <div class="row"><div class="label">Buyer wallet</div><div id="s1Subject" class="value muted">Loading...</div></div>
          <div class="row"><div class="label">Issuer key ID</div><div id="s1Issuer" class="value muted">Not issued yet</div></div>
          <div class="row"><div class="label">Schema / credential type</div><div id="s1Type" class="value muted">KYC_VERIFIED</div></div>
          <div class="row"><div class="label">Policy-safe claims</div><div id="s1Claims" class="value muted">Not available yet</div></div>
          <div class="row"><div class="label">Attestation status</div><div id="s1AttestationState" class="value muted">Missing</div></div>
          <div class="row"><div class="label">Storage</div><div class="value">Stored off-chain by the buyer</div></div>
          <div class="row"><div class="label">Issuer signature / digest</div><div id="s1Signature" class="value muted">Not available yet</div></div>
        </div>
      </section>

      <section id="tab-technical" class="tab-panel">
        <p class="technical-debug-note">Debug / follow-up view — run the interactive demo from <strong>Merchant Checkout</strong>. Values update as you complete verification there.</p>
        <div class="card">
          <h2>Technical Flow</h2>
          <div class="row"><div class="label">Verification Mode</div><div id="modeBadge" class="value"><span class="badge mode">Loading...</span></div></div>
          <div class="row"><div class="label">Buyer Wallet</div><div id="walletBuyer" class="value muted">Loading...</div></div>
          <div class="row"><div class="label">Merchant Wallet</div><div id="walletMerchant" class="value muted">Create request first</div></div>
          <div class="row"><div class="label">Verifier Public Key</div><div id="walletVerifier" class="value muted">Available after verification</div></div>
          <div class="row"><div class="label">Request PDA</div><div id="walletPda" class="value muted">Create request first</div></div>
          <div class="row"><div class="label">Checklist</div><div id="flowChecklist" class="value muted">No verification started</div></div>
        </div>

        <div class="flow">
          <div class="card">
            <h3 id="s1Title">Step 1: Buyer has reusable attestation</h3>
            <div class="row"><div class="label">Buyer Wallet</div><div id="techS1Subject" class="value muted">Not loaded yet</div></div>
            <div class="row"><div class="label">Attestation status</div><div id="techS1State" class="value muted">Missing</div></div>
          </div>

          <div class="card">
            <h3 id="s2Title">Step 2: Merchant creates verification request</h3>
            <div class="row"><div class="label">Status</div><div class="value"><span id="s2StageStatus" class="status">PENDING</span></div></div>
            <div class="row"><div class="label">Step note</div><div id="s2Note" class="value muted">Not created yet</div></div>
            <div class="row"><div class="label">Request ID</div><div id="s2RequestId" class="value muted">Not created yet</div></div>
            <div class="row"><div class="label">Request PDA</div><div id="s2Pda" class="value muted">Not created yet</div></div>
            <div class="row"><div class="label">Challenge Message</div><div id="s2Challenge" class="value muted">Not created yet</div></div>
          </div>

          <div class="card">
            <h3 id="s3Title">Step 3: Buyer signs request challenge</h3>
            <div class="row"><div class="label">Status</div><div class="value"><span id="s3StageStatus" class="status">PENDING</span></div></div>
            <div class="row"><div class="label">Signing status</div><div id="s3SigningStatus" class="value muted">Waiting for signature</div></div>
            <div class="row"><div class="label">Signature</div><div id="s3Signature" class="value muted">Not signed yet</div></div>
            <div class="row"><div class="label">Signature validation</div><div id="s3SignatureValid" class="value muted">Not validated yet</div></div>
          </div>

          <div class="card">
            <h3 id="s4Title">Step 4: Buyer submits proof</h3>
            <div class="row"><div class="label">Payload / note</div><div id="s4Input" class="value muted">Awaiting proof submission from Merchant Checkout</div></div>
            <div class="row"><div class="label">What is verified</div><div id="s4Checks" class="value muted"></div></div>
            <div class="row"><div class="label">Stage status</div><div class="value"><span id="s4StageStatus" class="status">PENDING</span></div></div>
          </div>

          <div class="card">
            <h3 id="s5Title">Step 5: ShieldPay verifies proof</h3>
            <div class="row"><div class="label">Stage status</div><div class="value"><span id="s5VerifyStageStatus" class="status">PENDING</span></div></div>
            <div class="row"><div class="label">Verification checklist</div><div id="s5Checklist" class="value muted">No verification yet</div></div>
          </div>

          <div class="card">
            <div class="solana-step-header">
              <h3 id="s6Title">Step 6: ShieldPay anchors result on Solana</h3>
              <span id="solanaAnchoredBadge" class="badge solana-anchored" hidden>Anchored on Solana</span>
            </div>
            <div class="row"><div class="label">Result</div><div id="s5Policy" class="value muted">No result yet</div></div>
            <div class="row"><div class="label">Request ID</div><div id="receiptRequestId" class="value muted">Not created yet</div></div>
            <div class="row"><div class="label">Request PDA</div><div id="receiptRequestPda" class="value muted">Not created yet</div></div>
            <div class="row"><div class="label">Attestation digest</div><div id="s5Digest" class="value muted">No digest yet</div></div>
            <div class="row"><div class="label">Verification mode</div><div id="receiptMode" class="value muted">Loading...</div></div>
            <div class="row"><div class="label">Verifier key ID</div><div id="receiptVerifier" class="value muted">Not available yet</div></div>
            <div class="row"><div class="label">Solana tx signature</div><div class="value"><div class="tx-sig-row"><code id="s5Tx" class="tx-sig muted">Not anchored yet</code><a id="solanaExplorerLink" class="explorer-link" href="#" target="_blank" rel="noopener noreferrer" hidden>Open Explorer</a></div></div></div>
            <div class="row"><div class="label">On-chain note</div><div class="value"><p id="s6PrivacyNote" class="privacy-callout">Only verification result and attestation digest are stored on-chain. Personal data is not stored on-chain.</p></div></div>
            <div class="row"><div class="label">Stage status</div><div class="value"><span id="s6StageStatus" class="status">PENDING</span></div></div>
          </div>
        </div>

        <div class="card">
          <h3>Backend logs</h3>
          <div id="backendLogs" class="logs">No backend events yet</div>
        </div>
      </section>
    </div>

    <script>
      let currentRequest = null;
      let currentCredential = null;
      let currentSasAttestation = null;
      let currentMode = "mock";
      /** Ed25519 pubkey hex — shown in UI as “buyer wallet”. */
      let buyerWallet = "";
      /** Same id as proof submission.subjectId / SAS subjectWallet (e.g. buyer_demo_1). Must match for negative SAS demo. */
      let sasBuyerSubjectId = "";
      const logs = [];
      let signatureReady = false;
      let simulatedSignature = null;
      let checkoutDecisionState = "WAITING";
      let finalVerificationStatus = null;
      let proofSubmitted = false;
      let lastVerificationAt = "";
      let lastSolanaTxSignature = "";
      let solanaClusterCfg = "localnet";
      let solanaRpcUrlCfg = "http://localhost:8899";

      async function call(path, method = "GET", body) {
        const res = await fetch(path, {
          method,
          headers: { "content-type": "application/json" },
          body: body ? JSON.stringify(body) : undefined
        });
        return { status: res.status, payload: await res.json() };
      }

      function ts() {
        return new Date().toLocaleTimeString();
      }

      function logLine(line) {
        logs.push("[" + ts() + "] " + line);
        document.getElementById("backendLogs").textContent = logs.join("\\n");
      }

      function shortValue(v) {
        if (!v || typeof v !== "string") return "n/a";
        if (v.length <= 20) return v;
        return v.slice(0, 8) + "..." + v.slice(-8);
      }

      function buildSolanaExplorerTxUrl(fullSignature) {
        var base = "https://explorer.solana.com/tx/" + encodeURIComponent(fullSignature);
        if (solanaClusterCfg === "devnet") {
          return base + "?cluster=devnet";
        }
        return base + "?cluster=custom&customUrl=" + encodeURIComponent(solanaRpcUrlCfg);
      }

      function applySolanaTxDisplay(shortLabel, fullSignature) {
        lastSolanaTxSignature = typeof fullSignature === "string" ? fullSignature : "";
        var txEl = document.getElementById("s5Tx");
        var linkEl = document.getElementById("solanaExplorerLink");
        var badge = document.getElementById("solanaAnchoredBadge");
        txEl.textContent = shortLabel;
        var isPlaceholder = shortLabel === "Not anchored yet" || shortLabel === "pending";
        txEl.classList.toggle("muted", isPlaceholder);
        var hasRealSig = lastSolanaTxSignature.length > 0;
        if (hasRealSig) {
          linkEl.href = buildSolanaExplorerTxUrl(lastSolanaTxSignature);
          linkEl.hidden = false;
          badge.hidden = false;
        } else {
          linkEl.hidden = true;
          linkEl.removeAttribute("href");
          badge.hidden = true;
        }
      }

      function resetSolanaAnchorSection() {
        applySolanaTxDisplay("Not anchored yet", "");
      }

      function setActiveTab(tabId) {
        document.querySelectorAll(".tab-btn").forEach((btn) => {
          btn.classList.toggle("active", btn.dataset.tab === tabId);
        });
        document.querySelectorAll(".tab-panel").forEach((panel) => {
          panel.classList.toggle("active", panel.id === "tab-" + tabId);
        });
      }

      function updateStepTitles() {
        document.getElementById("s1Title").textContent = "Step 1: Buyer has reusable attestation";
        document.getElementById("s2Title").textContent = "Step 2: Merchant creates verification request";
        document.getElementById("s3Title").textContent = "Step 3: Buyer signs request challenge";
        document.getElementById("s4Title").textContent = "Step 4: Buyer submits proof";
        document.getElementById("s5Title").textContent = "Step 5: ShieldPay verifies proof";
        document.getElementById("s6Title").textContent = "Step 6: ShieldPay anchors result on Solana";
      }

      function setStageStatus(id, label) {
        document.getElementById(id).textContent = label;
      }

      function updateButtons() {
        const signBtn = document.getElementById("modalSignRequest");
        const submitBtn = document.getElementById("modalSubmitProof");
        if (!signBtn || !submitBtn) return;
        signBtn.disabled = !currentRequest || signatureReady;
        submitBtn.disabled = !currentRequest || !signatureReady;
      }

      function resetVerificationModal() {
        document.getElementById("modalSignSuccess").classList.remove("visible");
        document.getElementById("modalProgress").textContent = "";
        updateButtons();
      }

      function openVerificationModal() {
        document.getElementById("modalBuyerWallet").textContent = shortValue(buyerWallet);
        resetVerificationModal();
        document.getElementById("shieldpayModal").classList.add("open");
      }

      function closeVerificationModal() {
        document.getElementById("shieldpayModal").classList.remove("open");
        document.getElementById("modalProgress").textContent = "";
      }

      function updateTechnicalStep4Copy() {
        const checks = currentMode === "mock"
          ? "After submit: mock issuer-signed credential, schema, policy claims, expiry, buyer signature."
          : "After submit: SAS-style attestation, schema, policy claims, expiry, buyer signature.";
        document.getElementById("s4Checks").textContent = checks;
      }

      function updateIssuerTabMode() {
        const isMock = currentMode === "mock";
        document.getElementById("issuerTitle").textContent = isMock ? "Demo Issuer" : "SAS Attestation Service";
        document.getElementById("issuerDescription").textContent = isMock
          ? "In mock mode, ShieldPay simulates a KYC issuer signing a reusable buyer credential."
          : "In SAS mode, ShieldPay loads a SAS-style attestation for the buyer wallet.";
        document.getElementById("issue").style.display = isMock ? "inline-block" : "none";
        document.getElementById("issueNegativeMock").style.display = isMock ? "inline-block" : "none";
        document.getElementById("loadSas").style.display = isMock ? "none" : "inline-block";
        document.getElementById("loadSasNegative").style.display = isMock ? "none" : "inline-block";
      }

      function syncAttestationSummary() {
        document.getElementById("techS1Subject").textContent = document.getElementById("s1Subject").textContent;
        document.getElementById("techS1State").textContent = document.getElementById("s1AttestationState").textContent;
      }

      function decisionMetaHtml() {
        const pda = document.getElementById("walletPda").textContent.trim();
        const tx = document.getElementById("s5Tx").textContent.trim();
        const mode = (currentMode || "").toUpperCase();
        const t = lastVerificationAt || "—";
        return (
          "Verification mode: <strong>" + mode + "</strong><br />" +
          "Verification time: <strong>" + t + "</strong><br />" +
          "Request PDA: <strong>" + shortValue(pda) + "</strong><br />" +
          "Solana tx: <strong>" + tx + "</strong>"
        );
      }

      function renderCheckoutDecision() {
        const card = document.getElementById("merchantDecisionCard");
        const badge = document.getElementById("decisionBadge");
        const title = document.getElementById("checkoutDecisionTitle");
        const note = document.getElementById("checkoutDecisionNote");
        const meta = document.getElementById("checkoutDecisionMeta");
        const continueBtn = document.getElementById("continuePayment");
        badge.style.display = "none";
        badge.textContent = "";
        note.style.display = "none";
        note.textContent = "";
        meta.style.display = "none";
        meta.innerHTML = "";
        card.className = "merchant-decision pending";
        continueBtn.style.display = "none";
        if (!currentRequest) {
          title.textContent = "Waiting for verification";
          return;
        }
        if (finalVerificationStatus === "APPROVED") {
          card.className = "merchant-decision ok";
          badge.style.display = "inline-flex";
          badge.textContent = "Approved";
          badge.className = "badge approved";
          title.textContent = "Buyer passed the verification policy.";
          meta.style.display = "block";
          meta.innerHTML = decisionMetaHtml();
          continueBtn.style.display = "inline-block";
          return;
        }
        if (finalVerificationStatus === "REJECTED") {
          card.className = "merchant-decision bad";
          badge.style.display = "inline-flex";
          badge.textContent = "Rejected";
          badge.className = "badge rejected";
          title.textContent = "Buyer did not meet the verification policy.";
          note.style.display = "block";
          note.textContent = "Merchant should block or manually review this order.";
          meta.style.display = "block";
          meta.innerHTML = decisionMetaHtml();
          return;
        }
        continueBtn.style.display = "none";
        if (!signatureReady) {
          title.textContent = "Waiting for buyer signature";
          return;
        }
        if (!proofSubmitted) {
          title.textContent = "Waiting for proof submission";
          return;
        }
        if (checkoutDecisionState === "PENDING") {
          title.textContent = "Verification pending";
          return;
        }
        title.textContent = "Waiting for proof submission";
      }

      function renderFlowChecklist(trace, hasChallengeSignature, hasSasOrCredential, txSignature) {
        const items = [
          ["wallet connected / buyer wallet selected", Boolean(sasBuyerSubjectId || buyerWallet)],
          ["challenge signed", hasChallengeSignature],
          ["verification mode selected", currentMode === "mock" || currentMode === "sas"],
          ["credential or SAS attestation found", hasSasOrCredential],
          ["issuer trusted", Boolean(trace && trace.issuerTrusted)],
          ["policy passed", Boolean(trace && trace.credentialTypeValid && trace.kycStatusValid && trace.ageCheckPassed)],
          ["result anchored on Solana", Boolean(txSignature)],
        ];
        return items.map(([name, ok]) => (ok ? "✅ " : "❌ ") + name).join(" | ");
      }

      function renderChecklist(trace) {
        if (!trace) return "No verification yet";
        const items = [
          ["trusted issuer", trace.issuerTrusted],
          ["issuer signature", trace.issuerSignatureValid],
          ["credential expiry", trace.credentialNotExpired],
          ["credential type", trace.credentialTypeValid],
          ["KYC status", trace.kycStatusValid],
          ["age check", trace.ageCheckPassed],
          ["buyer challenge signature", trace.customerSignatureValid]
        ];
        return items.map(([name, ok]) => (ok ? "✅ " : "❌ ") + name).join(" | ");
      }

      async function initialize() {
        const config = await call("/api/config");
        currentMode = (config.payload && config.payload.verificationMode) || "mock";
        solanaClusterCfg = (config.payload && config.payload.solanaCluster) || "localnet";
        solanaRpcUrlCfg = (config.payload && config.payload.solanaRpcUrl) || "http://localhost:8899";
        document.getElementById("modeBadge").innerHTML =
          '<span class="badge mode">' + (currentMode === "sas" ? "SAS attestation mode" : "Mock signed credential mode") + '</span>';
        document.getElementById("receiptMode").textContent = currentMode.toUpperCase();
        updateStepTitles();
        updateTechnicalStep4Copy();
        updateIssuerTabMode();

        const customer = await call("/api/customer");
        buyerWallet = customer.payload && customer.payload.buyerWallet ? customer.payload.buyerWallet : "";
        sasBuyerSubjectId =
          (customer.payload && customer.payload.subjectId) ? String(customer.payload.subjectId) : buyerWallet;
        document.getElementById("walletBuyer").textContent = shortValue(buyerWallet);
        document.getElementById("checkoutBuyerWallet").textContent = shortValue(buyerWallet);
        document.getElementById("s1Subject").textContent =
          currentMode === "sas"
            ? sasBuyerSubjectId + " · " + shortValue(buyerWallet)
            : shortValue(buyerWallet);
        syncAttestationSummary();
        renderCheckoutDecision();
        logLine(
          "[mode] selected mode=" +
            currentMode +
            " sasSubject=" +
            sasBuyerSubjectId +
            " buyerWallet=" +
            shortValue(buyerWallet),
        );
        updateButtons();
      }

      async function issueMockCredential(negative = false) {
        const result = await call("/api/buyer/issue-credential", "POST", {});
        if (result.status >= 400) return;
        currentCredential = result.payload.credential;
        if (negative) {
          currentCredential = {
            ...currentCredential,
            claims: {
              ...currentCredential.claims,
              kycStatus: "REJECTED",
              ageOver18: false
            }
          };
        }
        currentSasAttestation = null;
        document.getElementById("s1Issuer").textContent = currentCredential.issuerKeyId;
        document.getElementById("s1Type").textContent = currentCredential.credentialType;
        document.getElementById("s1Claims").textContent =
          "kycStatus=" + currentCredential.claims.kycStatus + ", country=" + currentCredential.claims.country + ", ageOver18=" + currentCredential.claims.ageOver18;
        document.getElementById("s1Signature").textContent = shortValue(currentCredential.issuerSignatureHex);
        document.getElementById("s1AttestationState").textContent = negative ? "Negative" : "Valid";
        document.getElementById("s2Note").textContent = "Credential available in buyer wallet/app (off-chain demo state)";
        syncAttestationSummary();
        logLine(negative
          ? "[mock] negative credential issued for buyerWallet=" + shortValue(buyerWallet)
          : "[mock] credential issued for buyerWallet=" + shortValue(buyerWallet));
      }

      async function loadSasAttestation(negative = false) {
        const sasSubject = sasBuyerSubjectId || buyerWallet;
        if (!sasSubject) return;
        const result = await call(
          "/api/sas/attestation?subject=" + encodeURIComponent(sasSubject) + (negative ? "&negative=true" : "")
        );
        if (result.status >= 400) return;
        currentSasAttestation = result.payload.attestation;
        currentCredential = null;
        document.getElementById("s1Issuer").textContent = currentSasAttestation.issuer;
        document.getElementById("s1Type").textContent = currentSasAttestation.schemaType;
        var cl = currentSasAttestation.claims || {};
        document.getElementById("s1Claims").textContent =
          "kycStatus=" +
          (cl.kycStatus != null && String(cl.kycStatus) !== "" ? String(cl.kycStatus) : "UNKNOWN") +
          ", country=" +
          (cl.country != null ? cl.country : "—") +
          ", ageOver18=" +
          (cl.ageOver18 !== undefined ? cl.ageOver18 : "—");
        document.getElementById("s1Signature").textContent = shortValue(currentSasAttestation.digestHex);
        document.getElementById("s1AttestationState").textContent = negative ? "Negative" : "Valid";
        document.getElementById("s2Note").textContent = negative
          ? "Negative SAS attestation loaded for demo"
          : "SAS attestation available for buyer wallet";
        syncAttestationSummary();
        logLine(negative
          ? "[sas] negative attestation loaded issuer=" + currentSasAttestation.issuer
          : "[sas] attestation found=" + Boolean(currentSasAttestation) + " issuer=" + currentSasAttestation.issuer);
      }

      async function createRequest() {
        const result = await call("/api/merchant/request", "POST", {});
        if (result.status >= 400) {
          logLine("[merchant-api] request failed status=" + result.status);
          return false;
        }
        currentRequest = result.payload;
        signatureReady = false;
        simulatedSignature = null;
        proofSubmitted = false;
        finalVerificationStatus = null;
        lastVerificationAt = "";
        checkoutDecisionState = "PENDING";
        resetVerificationModal();
        renderCheckoutDecision();
        document.getElementById("s2RequestId").textContent = currentRequest.requestId;
        document.getElementById("receiptRequestId").textContent = currentRequest.requestId;
        document.getElementById("s2Pda").textContent = currentRequest.requestPda || "n/a";
        document.getElementById("receiptRequestPda").textContent = currentRequest.requestPda || "n/a";
        document.getElementById("s2Challenge").textContent = shortValue(currentRequest.challenge);
        document.getElementById("s2Note").textContent = "Verification request created";
        document.getElementById("walletPda").textContent = currentRequest.requestPda || "n/a";
        document.getElementById("walletMerchant").textContent = shortValue(currentRequest.merchantWallet || "n/a");
        setStageStatus("s2StageStatus", "COMPLETED");
        setStageStatus("s3StageStatus", "READY");
        document.getElementById("s3SigningStatus").textContent = "Waiting for signature";
        document.getElementById("s3Signature").textContent = "Not signed yet";
        document.getElementById("s3SignatureValid").textContent = "Not validated yet";
        setStageStatus("s4StageStatus", "PENDING");
        setStageStatus("s5VerifyStageStatus", "PENDING");
        setStageStatus("s6StageStatus", "PENDING");
        resetSolanaAnchorSection();
        document.getElementById("s4Input").textContent =
          "Awaiting buyer signature and proof submission (Merchant Checkout modal).";
        updateButtons();
        logLine("[merchant-api] request created requestId=" + currentRequest.requestId + " mode=" + currentMode);
        return true;
      }

      async function handleSignChallenge() {
        if (!currentRequest) return;
        simulatedSignature = "sig_" + btoa(currentRequest.requestId).slice(0, 16);
        signatureReady = true;
        checkoutDecisionState = "PENDING";
        setStageStatus("s3StageStatus", "COMPLETED");
        setStageStatus("s4StageStatus", "READY");
        document.getElementById("s3SigningStatus").textContent = "Challenge signed";
        document.getElementById("s3Signature").textContent = shortValue(simulatedSignature);
        document.getElementById("s3SignatureValid").textContent = "Signature valid";
        document.getElementById("modalSignSuccess").classList.add("visible");
        renderCheckoutDecision();
        logLine("[sign] challenge signed=true requestId=" + currentRequest.requestId);
        updateButtons();
      }

      async function handleSubmitProof() {
        const progressEl = document.getElementById("modalProgress");
        const submitModalBtn = document.getElementById("modalSubmitProof");
        const signModalBtn = document.getElementById("modalSignRequest");
        if (!currentRequest) {
          document.getElementById("s4Input").textContent = "Create request first";
          return;
        }
        if (!signatureReady) {
          document.getElementById("s4Input").textContent = "Sign challenge first";
          progressEl.textContent = "Sign the verification request first.";
          return;
        }
        if (!currentCredential && currentMode === "mock") {
          document.getElementById("s4Input").textContent = "Issue credential first";
          progressEl.textContent = "Issue a mock credential under Issuer / SAS, then retry.";
          return;
        }
        checkoutDecisionState = "PENDING";
        renderCheckoutDecision();
        submitModalBtn.disabled = true;
        signModalBtn.disabled = true;
        progressEl.innerHTML = '<span class="spinner"></span>Submitting proof...';
        document.getElementById("s4Input").textContent = "Submitting proof to ShieldPay…";
        const result = await call("/api/buyer/submit", "POST", { request: currentRequest });
        if (result.status >= 400) {
          document.getElementById("s4Input").textContent = result.payload.error || "Submit failed";
          progressEl.textContent = result.payload.error || "Submit failed";
          submitModalBtn.disabled = false;
          signModalBtn.disabled = false;
          return;
        }
        progressEl.innerHTML = '<span class="spinner"></span>ShieldPay is verifying attestation...';
        await new Promise((r) => setTimeout(r, 450));
        progressEl.innerHTML = '<span class="spinner"></span>Anchoring result on Solana...';
        await new Promise((r) => setTimeout(r, 450));
        proofSubmitted = true;
        const metadata = result.payload.demoMetadata || {};
        document.getElementById("s2Pda").textContent = metadata.requestPda || "n/a";
        document.getElementById("receiptRequestPda").textContent = metadata.requestPda || "n/a";
        document.getElementById("walletPda").textContent = metadata.requestPda || "n/a";
        document.getElementById("s4Input").textContent = "Proof payload submitted to merchant API.";
        setStageStatus("s4StageStatus", "COMPLETED");
        setStageStatus("s5VerifyStageStatus", "COMPLETED");
        document.getElementById("s5Checklist").textContent = renderChecklist(result.payload.verificationTrace);
        document.getElementById("flowChecklist").textContent = renderFlowChecklist(
          result.payload.verificationTrace,
          Boolean(metadata.customerSignatureHex),
          currentMode === "sas" ? Boolean(currentSasAttestation) : Boolean(currentCredential),
          metadata.transactionSignature
        );
        document.getElementById("s5Digest").textContent = metadata.attestationDigest || "n/a";
        var rawSig = metadata.transactionSignature;
        if (rawSig) {
          applySolanaTxDisplay(shortValue(rawSig), rawSig);
        } else {
          applySolanaTxDisplay("pending", "");
        }
        document.getElementById("walletVerifier").textContent = result.payload.verifierKeyId || "n/a";
        document.getElementById("receiptVerifier").textContent = result.payload.verifierKeyId || "n/a";
        finalVerificationStatus =
          result.payload.result && result.payload.result.status === "APPROVED" ? "APPROVED" : "REJECTED";
        document.getElementById("s5Policy").textContent = finalVerificationStatus;
        checkoutDecisionState = finalVerificationStatus;
        lastVerificationAt = new Date().toLocaleString();
        setStageStatus("s6StageStatus", "COMPLETED");
        renderCheckoutDecision();
        progressEl.textContent = "Verification complete.";
        closeVerificationModal();
        logLine("[mode] selected mode=" + currentMode);
        logLine("[proof-service] sasSubject=" + sasBuyerSubjectId + " buyerWallet=" + shortValue(buyerWallet));
        logLine("[sas] attestation found=" + String(currentMode === "sas" ? Boolean(currentSasAttestation) : Boolean(currentCredential)));
        logLine("[sas] issuer trusted=" + String(result.payload.verificationTrace?.issuerTrusted ?? false));
        logLine("[policy] passed=" + String(result.payload.result?.status === "APPROVED"));
        logLine("[solana] tx=" + shortValue(metadata.transactionSignature || "pending"));
        updateButtons();
      }

      document.querySelectorAll(".tab-btn").forEach((btn) => {
        btn.onclick = () => setActiveTab(btn.dataset.tab);
      });

      document.getElementById("issue").onclick = () => issueMockCredential(false);
      document.getElementById("issueNegativeMock").onclick = () => issueMockCredential(true);
      document.getElementById("loadSas").onclick = () => loadSasAttestation(false);
      document.getElementById("loadSasNegative").onclick = () => loadSasAttestation(true);

      document.getElementById("verifyBuyer").onclick = async () => {
        const btn = document.getElementById("verifyBuyer");
        const hint = document.getElementById("verifyLoadingHint");
        btn.disabled = true;
        hint.innerHTML = '<span class="spinner"></span>Creating verification request...';
        const ok = await createRequest();
        btn.disabled = false;
        hint.textContent = "";
        if (ok) {
          openVerificationModal();
        }
      };

      document.getElementById("modalSignRequest").onclick = handleSignChallenge;
      document.getElementById("modalSubmitProof").onclick = handleSubmitProof;

      document.getElementById("continuePayment").onclick = () => {
        logLine("[merchant] continue to payment clicked requestId=" + (currentRequest ? currentRequest.requestId : "n/a"));
      };

      initialize();
    </script>
  </body>
</html>`;
}
