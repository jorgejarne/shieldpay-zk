# ShieldPay ZK Architecture

## Product Objective

ShieldPay ZK is a merchant-first fraud gatekeeper on Solana. Before accepting a payment-related action, a merchant requires a cryptographic verification result proving that the buyer controls an authorized credential source.

## MVP System Components

### On-chain (`programs/shieldpay_gatekeeper`)
- Store deterministic verification request metadata (merchant, challenge hash, window, status).
- Commit minimal verification outcome references (attestation digest + status + verifier key id).
- Enforce replay and stale-window protections at state transition boundaries.
- Use one mutable request PDA per request lifecycle for MVP simplicity.
- Store only `challenge_hash` on-chain (raw challenge remains off-chain).
- Use a config PDA with authority-controlled active verifier key updates.

### Off-chain Proof/Credential Service (`apps/proof-service`, planned)
- Accept credential envelopes and proof submissions.
- Validate credential policies (issuer allowlist/revocation/expiry).
- Run pluggable verifier interface:
  - `AttestationVerifier` for signed credentials (MVP default).
  - `ZkVerifier` adapter for future ZK circuits.

### Merchant API (`apps/merchant-api`, planned)
- Create verification requests for checkout actions.
- Read verification status and provide merchant-facing decision payload.
- Submit on-chain commit transactions after successful verification.

### Frontend Demo (`apps/demo-web`, planned)
- Buyer flow for request retrieval and proof submission.
- Merchant view for status polling and final decision display.

### Shared Types + SDK (`packages/*`)
- `@shieldpay/shared-types`: canonical request/credential/proof/result schemas.
- `@shieldpay/verification-core`: deterministic security-critical verification decision logic.
- `@shieldpay/config`: validated environment config module.

## On-chain vs Off-chain Rationale

- Keep sensitive credential verification off-chain to avoid leaking identifiers, reduce compute costs, and support cryptographic agility.
- Keep request identity, final status anchor, and auditable digest on-chain for non-repudiation and merchant trust.
- Use off-chain signature/ZK verification with on-chain digest commitments for practical devnet MVP performance.

## Recommended Cryptography Path for MVP

1. **Now:** Anchor + signed credential attestations (Ed25519), modular verifier interface.
2. **Next:** Add optional Anchor integration with Solana-native primitives where useful (e.g., sysvar-based timing checks, signer validations).
3. **Later:** Evaluate Light Protocol/compressed state only when request volume and account-rent pressure justify added complexity.

## Task 1 (Implemented)

- Bootstrapped strict TypeScript monorepo foundations.
- Implemented deterministic verification core using real Ed25519 verification.
- Added config validation and tests for replay-window safety controls.
- Added security-critical tests for approval, stale replay rejection, and challenge substitution rejection.

## Task 2 (Implemented)

- Added `apps/proof-service` with an `IssuerPolicy` interface and `ShieldPaySingleIssuerPolicy` implementation for a single ShieldPay issuer MVP model.
- Added one global verifier signer model that returns `SignedAttestation` containing `verifierKeyId` for future key rotation compatibility.
- Added `apps/merchant-api` orchestration service for request lifecycle: `PENDING -> APPROVED|REJECTED|EXPIRED`.
- Added integration tests for end-to-end off-chain flow:
  - merchant creates request
  - user submits credential and signed proof
  - proof service verifies and signs attestation
  - merchant reads final status view

## Task 3 (Implemented)

- Added Anchor program scaffold in `programs/shieldpay_gatekeeper`.
- Implemented single-request-PDA lifecycle with mutable status:
  - `Pending`
  - `Approved`
  - `Rejected`
  - `Expired`
- Implemented challenge privacy boundary by storing only `challenge_hash`.
- Implemented verifier authorization via config PDA and updatable active verifier key.
- Added instruction/account documentation in `docs/shieldpay_gatekeeper_program.md`.

## Task 4 (Implemented)

- Added shared Solana SDK package `@shieldpay/solana-gatekeeper-sdk` with explicit helpers:
  - localnet/devnet RPC selection
  - config/request PDA derivation
  - create/commit instruction builders
  - request account decoder for status reads
- Wired merchant API to optional on-chain anchoring client:
  - create request -> on-chain `create_request`
  - submit verified result -> on-chain `commit_result`
  - read final anchored status via request PDA decode
- Added `MerchantSolanaAnchoringClient` for localnet-first and devnet-ready usage.
- Added integration tests for:
  - create request and anchored `PENDING`
  - commit `APPROVED` and read anchored final status
  - commit `REJECTED` and read anchored final status

## Important Current Boundary

On-chain state currently anchors verifier-approved/rejected digests and statuses. The program does not yet fully re-verify complete off-chain attestation payload semantics on-chain.

## Task 5 (Implemented)

- Added HTTP merchant API server wrapper in `apps/merchant-api/src/server.ts` with endpoints:
  - `POST /requests`
  - `GET /requests/:requestId/status`
  - `GET /requests/:requestId/anchored-status`
  - `POST /requests/:requestId/proof`
- Added local demo identity helper (`apps/merchant-api/src/demoIdentity.ts`) for Ed25519 buyer identity generation, mock credential creation, and canonical proof signing.
- Added `apps/demo-web` with merchant and buyer panels for local end-to-end MVP interaction.
- Added explicit operational logs for request creation, proof submission, credential verification, attestation signing, Solana create/commit sends, and final status reads.
