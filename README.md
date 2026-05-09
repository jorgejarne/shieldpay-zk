
# ShieldPay ZK MVP

Merchant-first fraud gatekeeper on Solana.  
Current MVP path verifies credentials/proofs off-chain, then anchors verifier-approved/rejected digest + status on-chain.
This MVP remains **signed-credential based** (no ZK circuits yet).

## WSL-First Environment Assumption

All Solana/Anchor/Rust commands are expected to run inside **WSL Ubuntu**, not native Windows PowerShell.

- Run this repo from a Linux path, for example: `/home/<you>/projects/shieldpay-zk`
- Prefer keeping Solana keypairs/config inside WSL home (for example `~/.config/solana/`)
- Use the same WSL terminal session for validator, Anchor deploy, and localnet tests

### Windows vs WSL caveat (brief)

- If files are kept on a Windows-mounted path (`/mnt/c/...`), I/O can be slower and tooling can feel less stable.
- Prefer cloning/copying the repo into the WSL filesystem (`/home/...`) for smoother Anchor/Solana workflows.

## Current Security Boundary

- On-chain currently anchors request lifecycle status and verifier-submitted digest references.
- On-chain does **not** fully re-verify the complete off-chain attestation payload semantics yet.

## Required Toolchain (WSL Ubuntu)

- Node.js: `>=20.0.0` (recommended `>=20.18.0`)
- npm: `>=10`
- Rust toolchain: stable current
- Solana CLI: `1.18+` recommended
- Anchor CLI: `0.31.x` (matches `anchor-lang = 0.31.1`)

### Toolchain checks (run in WSL)

```bash
node -v
npm -v
rustc --version
cargo --version
solana --version
anchor --version
```

## Install (WSL)

```bash
npm install
```

## Run the Local MVP (WSL, 4 terminals)

Terminal 1 (validator):
```bash
solana-test-validator
```

Terminal 2 (build + deploy program):
```bash
anchor build && anchor deploy
```

Terminal 3 (merchant API):
```bash
npm run dev:merchant-api
```

Terminal 4 (demo web):
```bash
npm run dev:demo-web
```

Open the demo UI in Windows browser at `http://127.0.0.1:4173`.

### Optional Terminal 5 (SAS mock service)

Run this when using `VERIFICATION_MODE=sas`:

```bash
npm run dev:mock-sas-service
```

## Merchant API Endpoints

- `POST /requests`
- `GET /requests/:requestId/status`
- `GET /requests/:requestId/anchored-status`
- `POST /requests/:requestId/proof`

Default merchant API URL: `http://127.0.0.1:3000`.

## Workspace Checks

```bash
npm test
npm run lint
```

## Anchor Program Test

```bash
anchor test
```

`anchor test` requires Rust + Solana CLI + Anchor CLI installed and available in `PATH` inside WSL.

## Localnet Runtime Integration Tests (Narrow MVP Path)

The runtime suite includes exactly:
1. Happy path: `create_request -> commit_result(APPROVED) -> read final status`
2. Authorization failure: unauthorized verifier commit must fail
3. Invalid transition: second commit after finalization must fail

Test file: `tests/localnet-runtime.test.ts`

### Runtime flow (what runs what)

1. **Validator process**  
   `solana-test-validator` starts the local RPC node on `http://127.0.0.1:8899`.
2. **Program build/deploy step**  
   `anchor build && anchor deploy` compiles and deploys `shieldpay_gatekeeper` to that local validator.
3. **TypeScript runtime tests**  
   `RUN_LOCALNET_TESTS=1 npm run test:localnet` runs Vitest, which sends real transactions to the validator via `@solana/web3.js`.
4. **Status verification**  
   Tests read request PDA account data back from localnet and assert final status.

## Demo Runtime Flow

1. Merchant panel calls `POST /requests` to create a verification request.
2. Buyer panel uses local demo identity helper to:
   - generate customer Ed25519 identity
   - create a mock credential envelope
   - sign canonical proof message for that request challenge
3. Buyer panel submits credential + signed proof to `POST /requests/:requestId/proof`.
4. Merchant panel polls:
   - API status via `GET /requests/:requestId/status`
   - anchored status via `GET /requests/:requestId/anchored-status`
<img width="1267" height="788" alt="scheme" src="https://github.com/user-attachments/assets/6542a236-c70d-4495-9af9-1467d7a2eaf3" />
## Verification Modes (Mock vs SAS)

ShieldPay supports two verification backends selected with:

```bash
VERIFICATION_MODE=mock   # default
# or
VERIFICATION_MODE=sas
```

- `mock` mode:
  - Uses the current signed mock credential + proof flow.
  - Keeps existing MVP behavior for local demos/tests.
- `sas` mode:
  - Checks whether the buyer wallet has a valid Solana Attestation Service (SAS) attestation.
  - Applies ShieldPay policy checks (trusted issuer, schema/type like `KYC_VERIFIED`, optional claims like `ageOver18` and allowed country).
  - Keeps raw KYC attributes off-chain; only decision references/hashes are anchored.
  - **Local demo:** run `npm run dev:mock-sas-service` (port 3100) as well as demo-web and merchant-api. By default the merchant resolves SAS via demo-web (`http://127.0.0.1:4173/api/sas/attestations/latest`), which forwards to the mock SAS and applies the Issuer-tab “negative attestation” choice; override with `SAS_ATTESTATION_ENDPOINT=http://127.0.0.1:3100/sas/attestations/latest` if you omit demo-web. In the Issuer / SAS UI, **`GET /api/sas/attestation?subject=…&negative=…`** also pins that buyer for verifier lookups (single request—no separate “demo mode” POST).

### Local mock SAS endpoint

The local SAS mock service exposes:

- `GET /sas/attestations/latest?subject=<buyerWallet>`

Example:

Use the same `subject` string the buyer submits as `ProofSubmission.subjectId` (demo default is `buyer_demo_1`, not the hex pubkey):

```bash
curl "http://127.0.0.1:3100/sas/attestations/latest?subject=buyer_demo_1"
```

Negative policy demo response:

```bash
curl "http://127.0.0.1:3100/sas/attestations/latest?subject=buyer_demo_1&negative=true"
```

When `negative=true`, the mock attestation returns:

- `issuer=untrusted_issuer`
- `claims.kycStatus=REJECTED`
- `claims.country=US`
- `claims.ageOver18=false`

When `negative` is false, `claims.kycStatus` is `VERIFIED`.

### Why SAS

SAS enables a reusable "KYC passport" pattern: users can prove they already passed identity checks without re-running full KYC for every merchant interaction.

### Why ShieldPay still anchors payment decisions

ShieldPay continues to anchor the payment-specific verification decision (`APPROVED`/`REJECTED`) per request so merchants and auditors can verify the exact decision taken for that payment context, without exposing raw personal data on-chain.

### Run localnet tests manually (recommended)

Terminal A (keep running):
```bash
solana-test-validator
```

Terminal B:
```bash
anchor build
anchor deploy
RUN_LOCALNET_TESTS=1 npm run test:localnet
```

If `RUN_LOCALNET_TESTS` is not `1`, runtime tests are skipped by design.

### Using `--skip-local-validator`

If you already started a validator manually, you can run:

```bash
anchor test --skip-local-validator
```

This tells Anchor not to spawn its own validator and to use the existing one.

## Localnet vs Devnet

The merchant anchoring client supports localnet-first and devnet:

- localnet
  - `cluster: "localnet"`
  - default RPC: `http://127.0.0.1:8899`
- devnet
  - `cluster: "devnet"`
  - default RPC: `https://api.devnet.solana.com`

You can override RPC explicitly with `rpcUrl`.

`MerchantSolanaAnchoringClient` options:
- `cluster: "localnet" | "devnet"`
- `rpcUrl?: string`
- `merchantSigner`
- `verifierSigner`
- `programId?`

Set `SOLANA_CLUSTER=devnet` (and optionally `SOLANA_RPC_URL`) before running `npm run dev:merchant-api` to switch the API anchoring client to devnet.

## Node Version Caveat

`npm install` may show `EBADENGINE` warnings on Node `20.14.x` for some Solana codec packages requiring `>=20.18.0`.  
Current test/lint workflows pass, but upgrading to Node `20.18+` is recommended for smoother compatibility.
