use anchor_lang::prelude::*;

declare_id!("51tDw2neaMF7JaZboe58X39sMVQ5E5iJWUSRpLLyxjw7");

const CONFIG_SEED: &[u8] = b"config";
const REQUEST_SEED: &[u8] = b"request";

#[program]
pub mod shieldpay_gatekeeper {
    use super::*;

    pub fn initialize_config(
        ctx: Context<InitializeConfig>,
        authority: Pubkey,
        active_verifier: Pubkey,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.authority = authority;
        config.active_verifier = active_verifier;
        config.bump = ctx.bumps.config;
        Ok(())
    }

    pub fn update_verifier_key(
        ctx: Context<UpdateVerifierKey>,
        next_active_verifier: Pubkey,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.active_verifier = next_active_verifier;
        Ok(())
    }

    pub fn create_request(
        ctx: Context<CreateRequest>,
        args: CreateRequestArgs,
    ) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        require!(
            args.expires_at > now,
            ShieldpayError::InvalidExpiryWindow
        );

        let request = &mut ctx.accounts.request;
        request.merchant = ctx.accounts.merchant.key();
        request.request_id = args.request_id;
        request.challenge_hash = args.challenge_hash;
        request.status = VerificationStatus::Pending;
        request.created_at = now;
        request.expires_at = args.expires_at;
        request.attestation_digest = [0u8; 32];
        request.verifier_key_id_hash = [0u8; 32];
        request.bump = ctx.bumps.request;
        Ok(())
    }

    pub fn commit_result(
        ctx: Context<CommitResult>,
        args: CommitResultArgs,
    ) -> Result<()> {
        let request = &mut ctx.accounts.request;
        let config = &ctx.accounts.config;
        let now = Clock::get()?.unix_timestamp;

        require!(
            ctx.accounts.verifier.key() == config.active_verifier,
            ShieldpayError::UnauthorizedVerifier
        );
        require!(
            request.status == VerificationStatus::Pending,
            ShieldpayError::RequestAlreadyFinalized
        );
        require!(
            args.status != VerificationStatus::Pending,
            ShieldpayError::InvalidFinalStatus
        );
        require!(
            request.challenge_hash == args.challenge_hash,
            ShieldpayError::ChallengeHashMismatch
        );

        if now > request.expires_at && args.status != VerificationStatus::Expired {
            return err!(ShieldpayError::ExpiredRequestMustUseExpiredStatus);
        }

        request.status = args.status;
        request.attestation_digest = args.attestation_digest;
        request.verifier_key_id_hash = args.verifier_key_id_hash;
        Ok(())
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct CreateRequestArgs {
    pub request_id: [u8; 16],
    pub challenge_hash: [u8; 32],
    pub expires_at: i64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct CommitResultArgs {
    pub challenge_hash: [u8; 32],
    pub status: VerificationStatus,
    pub attestation_digest: [u8; 32],
    pub verifier_key_id_hash: [u8; 32],
}

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = 8 + VerifierConfig::INIT_SPACE,
        seeds = [CONFIG_SEED],
        bump
    )]
    pub config: Account<'info, VerifierConfig>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateVerifierKey<'info> {
    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bump,
        has_one = authority
    )]
    pub config: Account<'info, VerifierConfig>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(args: CreateRequestArgs)]
pub struct CreateRequest<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    pub merchant: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = 8 + VerificationRequestAccount::INIT_SPACE,
        seeds = [REQUEST_SEED, merchant.key().as_ref(), &args.request_id],
        bump
    )]
    pub request: Account<'info, VerificationRequestAccount>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CommitResult<'info> {
    #[account(
        seeds = [CONFIG_SEED],
        bump = config.bump
    )]
    pub config: Account<'info, VerifierConfig>,
    #[account(mut)]
    pub request: Account<'info, VerificationRequestAccount>,
    pub verifier: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct VerifierConfig {
    pub authority: Pubkey,
    pub active_verifier: Pubkey,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct VerificationRequestAccount {
    pub merchant: Pubkey,
    pub request_id: [u8; 16],
    pub challenge_hash: [u8; 32],
    pub status: VerificationStatus,
    pub created_at: i64,
    pub expires_at: i64,
    pub attestation_digest: [u8; 32],
    pub verifier_key_id_hash: [u8; 32],
    pub bump: u8,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq, InitSpace)]
pub enum VerificationStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[error_code]
pub enum ShieldpayError {
    #[msg("Only the configured verifier key can commit results.")]
    UnauthorizedVerifier,
    #[msg("Request already has a final status.")]
    RequestAlreadyFinalized,
    #[msg("Pending is not a valid final commit status.")]
    InvalidFinalStatus,
    #[msg("Challenge hash does not match request record.")]
    ChallengeHashMismatch,
    #[msg("Expiry must be in the future.")]
    InvalidExpiryWindow,
    #[msg("If request has expired, final status must be Expired.")]
    ExpiredRequestMustUseExpiredStatus,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_enum_order_is_stable() {
        assert_eq!(VerificationStatus::Pending as u8, 0);
        assert_eq!(VerificationStatus::Approved as u8, 1);
        assert_eq!(VerificationStatus::Rejected as u8, 2);
        assert_eq!(VerificationStatus::Expired as u8, 3);
    }

    #[test]
    fn request_account_space_is_large_enough() {
        assert!(VerificationRequestAccount::INIT_SPACE >= 130);
    }

    #[test]
    fn config_account_space_is_large_enough() {
        assert!(VerifierConfig::INIT_SPACE >= 65);
    }
}
