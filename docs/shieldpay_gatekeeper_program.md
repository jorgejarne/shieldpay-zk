# ShieldPay Gatekeeper Program

## PDA Model

- **Config PDA**
  - Seeds: `["config"]`
  - Stores: `authority`, `active_verifier`, `bump`
- **Request PDA (single account per request)**
  - Seeds: `["request", merchant_pubkey, request_id]`
  - Stores:
    - request identity: `merchant`, `request_id`
    - privacy-minimized anchor: `challenge_hash`
    - lifecycle status: `Pending | Approved | Rejected | Expired`
    - timing: `created_at`, `expires_at`
    - result reference: `attestation_digest`, `verifier_key_id_hash`
    - `bump`

## Instructions

- `initialize_config(authority, active_verifier)`
  - Creates config PDA.
  - Sets authority and one active verifier key.
- `update_verifier_key(next_active_verifier)`
  - Requires config authority signer.
  - Updates active verifier key without redeploy.
- `create_request({ request_id, challenge_hash, expires_at })`
  - Creates one request PDA.
  - Initializes status to `Pending`.
  - Rejects past/invalid expiry windows.
- `commit_result({ challenge_hash, status, attestation_digest, verifier_key_id_hash })`
  - Requires verifier signer equals config `active_verifier`.
  - Allows one final commit only from `Pending`.
  - Rejects `Pending` as commit status.
  - Enforces `challenge_hash` match.
  - If request already expired, only `Expired` final status is valid.

## Security Notes

- Raw challenge is never persisted on-chain.
- Final status is immutable once committed.
- Verifier rotation is config-authority controlled.
