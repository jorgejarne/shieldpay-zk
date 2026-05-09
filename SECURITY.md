# ShieldPay ZK Security Register

## Security Posture

This repository is for a high-risk fraud prevention product. Security-critical logic must be deterministic, test-covered, and free of placeholder cryptography in core paths.

## Threat Model Focus

- Replay attacks on stale submissions.
- Forged credentials or forged proofs.
- Proof substitution between requests/challenges.
- Signature confusion across domains or message formats.
- Stale verification windows and clock skew abuse.

## Controls Implemented (Task 1)

- Deterministic canonical proof message domain separation (`shieldpay.verification.v1`).
- Real Ed25519 signature verification in `@shieldpay/verification-core`.
- Replay resistance via `signedAtMs + verificationWindowMs` checks.
- Challenge binding to request-specific nonce.
- Credential type/subject/expiry/revocation checks before signature approval.
- Deterministic attestation digest generation for on-chain commitment.
- Strict config validation preventing insecure window/skew combinations.

## Controls Implemented (Task 2)

- Single ShieldPay issuer credential policy enforced via `IssuerPolicy` abstraction (future allowlists can be added without changing verification flow).
- Global verifier signing key model enforced in proof service; `verifierKeyId` persisted in signed attestation and status views for forward-compatible key rotation.
- Request lifecycle state includes `PENDING`, `APPROVED`, `REJECTED`, `EXPIRED` semantics in merchant orchestration.
- Integration tests cover request creation, valid approval path, and issuer-policy rejection path.

## Controls Implemented (Task 3)

- On-chain config account with authority-controlled verifier key rotation instruction.
- On-chain request record stores only `challenge_hash`; raw challenge remains off-chain.
- Request status can transition from `Pending` to one final status exactly once.
- Commit instruction requires signer equals configured active verifier key.
- Commit instruction rejects non-final status and challenge hash mismatches.
- Commit instruction requires `Expired` status if commit occurs after request expiry.

## Controls Implemented (Task 4)

- Merchant API can anchor request creation and final verifier decision to on-chain request PDA through explicit SDK calls.
- Shared SDK enforces deterministic PDA derivation and explicit instruction payload encoding for create/commit operations.
- Final anchored status can be read from chain via request account decoding.
- Integration tests verify end-to-end anchored flow semantics for `PENDING -> APPROVED` and `PENDING -> REJECTED`.

## Explicit Security Boundary

Current on-chain logic anchors verifier-submitted status and digest references. It does not yet re-verify the full off-chain attestation payload cryptographically on-chain.

## Controls Implemented (Task 5)

- Local demo buyer identity uses real Ed25519 signing over canonical request-bound challenge messages.
- Merchant API operational flow keeps signed-credential verification path unchanged (no ZK circuits added).
- Solana anchoring client now initializes/updates verifier config for local runtime and logs every anchor step.
- API endpoints cleanly separate request lifecycle reads from proof submission writes.

## Known Residual Risks

- Revocation set freshness is off-chain and requires robust sync strategy.
- No on-chain anti-front-running or commit-reveal in current step.
- No anti-front-running or commit-reveal mechanism yet.
- No secure key custody module yet (HSM/KMS integration pending).

## Security Gates Before Mainnet

- Independent cryptography review of canonical message and attestation format.
- Full integration tests across API, verifier, and Anchor program state transitions.
- Replay and substitution adversarial test suite at API boundary.
- Verifier signing keys moved to managed KMS/HSM with auditable access.
