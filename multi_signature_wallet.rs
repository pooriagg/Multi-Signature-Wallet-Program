use anchor_lang::prelude::*;
use anchor_lang::solana_program::native_token::{lamports_to_sol, sol_to_lamports};
use anchor_lang::system_program;

declare_id!("CXRfczTzun6GSY3NP43YRkr7CpnQPzPqLHJqDNg2LMSY");

#[program]
mod multi_signature_wallet {
    use super::*;

    const MAX_ADMINS_COUNT: u8 = 5;

    pub fn create_wallet(
        ctx: Context<CreateWallet>,
        wallet_id: u32,
        admins: Vec<Pubkey>,
        confirmation_needed: u8
    ) -> Result<()> {
        let wallet = &mut ctx.accounts.wallet;

        let admins_counts = admins.len();
        if admins_counts == 0 {
            return err!(Errors::AdminZeroCount);
        } else if admins_counts > MAX_ADMINS_COUNT.into() {
            return err!(Errors::AdminMaxCount);
        };

        if confirmation_needed == 0 {
            return err!(Errors::ConfirmationZeroCount);
        } else if usize::from(confirmation_needed) > admins_counts + 1 { // Owner also can vote
            return err!(Errors::ConfirmationMaxCount);
        };

        wallet.owner = ctx.accounts.user.key();
        wallet.bump = *ctx.bumps.get("wallet").unwrap();
        wallet.admins = admins;
        wallet.min_confirmation = confirmation_needed;
        wallet.wallet_id = wallet_id;

        emit!(NewWalletCreated {
            creator: ctx.accounts.user.key()
        });

        msg!("New wallet created.");
        msg!("Wallet id - {}", wallet_id);
        msg!("Wallet owner - {}", ctx.accounts.user.key());

        Ok(())
    }

    pub fn deposit_sol(
        ctx: Context<DepositSol>,
        wallet_id: u32,
        sol_amount: f64
    ) -> Result<()> {
        require!(sol_amount > 0.0, Errors::ZeroSOL);

        let lamports = sol_to_lamports(sol_amount);

        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.user.to_account_info().clone(),
                to: ctx.accounts.wallet.to_account_info().clone()
            },
        );
        system_program::transfer(cpi_context, lamports).unwrap();

        emit!(SolDeposited {
            wallet: ctx.accounts.wallet.key(),
            amount: sol_amount,
            from: ctx.accounts.user.key()
        });

        msg!("Sol deposited to wallet.");
        msg!("{} SOL", sol_amount);
        msg!("To wallet - {}", ctx.accounts.wallet.key());

        Ok(())
    }

    pub fn create_sol_payment(
        ctx: Context<CreatePayment>,
        wallet_id: u32,
        sol_amount: f64,
        target: Pubkey
    ) -> Result<()> {
        let wallet = &mut ctx.accounts.wallet;
        let payment = &mut ctx.accounts.paymet;

        let user = ctx.accounts.user.key();
        let is_valid = is_user_valid(&wallet.admins.clone(), &user);

        if is_valid == false {
            if wallet.owner != user {
                return err!(Errors::InvalidAccess);
            };
        };

        if sol_to_lamports(sol_amount) == 0 {
            return err!(Errors::ZeroSOL);
        };

        if sol_to_lamports(sol_amount) > wallet.to_account_info().lamports() {
            return err!(Errors::InsufficeintWalletBalance);
        };

        wallet.total_payments += 1;

        payment.amount = sol_to_lamports(sol_amount);
        payment.bump = *ctx.bumps.get("payment").unwrap();
        payment.payment_id = wallet.total_payments;
        payment.target = target;

        msg!("New payment created.");
        msg!("Payment id - {}", payment.payment_id);
        msg!("Payment for wallet-id {}", wallet.wallet_id);
        msg!("Payment amount - {} SOL", sol_amount);
        msg!("Payment target - {}", target);

        Ok(())
    }

    pub fn confirm_sol_payment(
        ctx: Context<ConfirmPayment>,
        wallet_id: u32,
        payment_id: u32
    ) -> Result<()> {
        let wallet = &mut ctx.accounts.wallet;
        let payment = &mut ctx.accounts.payment;

        let user = ctx.accounts.user.key();
        let is_valid = is_user_valid(&wallet.admins.clone(), &user);
        let is_voted = is_user_confirmed(&payment.confirm.clone(), &user);

        if is_valid == false {
            if wallet.owner != user {
                return err!(Errors::InvalidAccess);
            };
        };

        if payment.is_executed == true {
            return err!(Errors::PaymentAlreadyExecuted);
        };

        if is_voted == true {
            return err!(Errors::DuplicateVote);
        };

        payment.confirm.push(user);

        msg!("Payment confirmed.");
        msg!("Wallet - {}", wallet_id);
        msg!("Payment - {}", payment_id);

        Ok(())
    }

    pub fn revoke_sol_payment(
        ctx: Context<RevokePayment>,
        wallet_id: u32,
        payment_id: u32
    ) -> Result<()> {
        let wallet = &mut ctx.accounts.wallet;
        let payment = &mut ctx.accounts.payment;

        let user = ctx.accounts.user.key();
        let is_valid = is_user_valid(&wallet.admins.clone(), &user);
        let is_voted = is_user_confirmed(&payment.confirm.clone(), &user);

        if is_valid == false {
            if wallet.owner != user {
                return err!(Errors::InvalidAccess);
            };
        };

        if payment.is_executed == true {
            return err!(Errors::PaymentAlreadyExecuted);
        };

        if is_voted == false {
            return err!(Errors::NotVotedBefore);
        };

        let mut admin_index: usize = 0;
        for ( index, admin ) in payment.confirm.iter().enumerate() {
            if admin == &user {
                admin_index = index;
                break;
            };
        };
        payment.confirm.remove(admin_index);

        msg!("Confirmation canceled!");
        msg!("Wallet - {}", wallet_id);
        msg!("Payment - {}", payment_id);

        Ok(())
    }

    pub fn execute_sol_payment(
        ctx: Context<ExecutePayment>,
        wallet_id: u32,
        payment_id: u32
    ) -> Result<()> {
        let wallet = &mut ctx.accounts.wallet;
        let payment = &mut ctx.accounts.payment;

        let user = ctx.accounts.user.key();
        let is_voted = is_user_confirmed(&payment.confirm.clone(), &user);

        if is_voted == false && wallet.owner != user {
            return err!(Errors::YouCannotExecute);
        };

        if payment.is_executed == true {
            return err!(Errors::PaymentAlreadyExecuted);
        };

        if payment.confirm.len() < wallet.min_confirmation.into() {
            return err!(Errors::LowConfirmations);
        };

        if payment.amount > wallet.to_account_info().lamports() {
            return err!(Errors::InsufficeintWalletBalance);
        };

        payment.is_executed = true;

        **ctx.accounts.wallet.to_account_info().try_borrow_mut_lamports()? -= payment.amount; 
        **ctx.accounts.target.to_account_info().try_borrow_mut_lamports()? += payment.amount;

        emit!(PaymentExecuted {
            wallet: ctx.accounts.wallet.key(),
            payment: payment.key(),
            executer: user
        });

        msg!("Payment executed.");
        msg!("Payment - {}.", payment_id);
        msg!("Wallet - {}.", wallet_id);
        msg!("{} SOl, Transfered to {} address.", lamports_to_sol(payment.amount), payment.target);

        Ok(())
    }
}

pub fn is_user_valid(
    valid_users: &Vec<Pubkey>,
    user: &Pubkey
) -> bool {
    let result = valid_users.iter().position(|&admin| admin == *user);

    if result != None {
        return true;
    } else {
        return false;
    };
}

pub fn is_user_confirmed(
    voted_users: &Vec<Pubkey>,
    user: &Pubkey
) -> bool {
    let result = voted_users.iter().position(|&voter| voter == *user);

    if result == None {
        return false;
    } else {
        return true;
    };
}

#[derive(Accounts)]
#[instruction(wallet_id: u32)]
pub struct CreateWallet<'info> {
    #[account(
        init,
        payer = user,
        space = 8 + 32 + (4 + (5 * 32)) + 16 + 1 + 16 + 4 + 1,
        seeds = [ b"wallet".as_ref(), &wallet_id.to_le_bytes().as_ref() ],
        bump
    )]
    pub wallet: Account<'info, Wallet>,
    #[account(mut)]
    pub user: Signer<'info>,
    system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(wallet_id: u32)]
pub struct DepositSol<'info> {
    #[account(
        mut,
        seeds = [ b"wallet".as_ref(), &wallet_id.to_le_bytes().as_ref() ],
        bump = wallet.bump
    )]
    pub wallet: Account<'info, Wallet>,
    #[account()]
    pub user: Signer<'info>,
    system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(wallet_id: u32)]
pub struct CreatePayment<'info> {
    #[account(
        mut,
        seeds = [ b"wallet".as_ref(), &wallet_id.to_le_bytes().as_ref() ],
        bump = wallet.bump
    )]
    pub wallet: Account<'info, Wallet>,
    #[account(
        init,
        payer = user,
        space = 8 + (4 + (&wallet.admins.len() * 32)) + 8 + 1 + 4 + 1,
        seeds = [ b"payment".as_ref(), &(wallet.total_payments + 1).to_le_bytes().as_ref() ],
        bump
    )]
    pub paymet: Account<'info, Payment>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>
}

#[derive(Accounts)]
#[instruction(wallet_id: u32, payment_id: u32)]
pub struct ConfirmPayment<'info> {
    #[account(
        mut,
        seeds = [ b"payment".as_ref(), &payment_id.to_le_bytes().as_ref() ],
        bump = payment.bump
    )]
    pub payment: Account<'info, Payment>,
    #[account(
        mut,
        seeds = [ b"wallet".as_ref(), &wallet_id.to_le_bytes().as_ref() ],
        bump = wallet.bump
    )]
    pub wallet: Account<'info, Wallet>,
    #[account(mut)]
    pub user: Signer<'info>
}

#[derive(Accounts)]
#[instruction(wallet_id: u32, payment_id: u32)]
pub struct RevokePayment<'info> {
    #[account(
        mut,
        seeds = [ b"payment".as_ref(), &payment_id.to_le_bytes().as_ref() ],
        bump = payment.bump
    )]
    pub payment: Account<'info, Payment>,
    #[account(
        mut,
        seeds = [ b"wallet".as_ref(), &wallet_id.to_le_bytes().as_ref() ],
        bump = wallet.bump
    )]
    pub wallet: Account<'info, Wallet>,
    #[account(mut)]
    pub user: Signer<'info>
}

#[derive(Accounts)]
#[instruction(wallet_id: u32, payment_id: u32)]
pub struct ExecutePayment<'info> {
    #[account(
        mut,
        seeds = [ b"payment".as_ref(), &payment_id.to_le_bytes().as_ref() ],
        bump = payment.bump,
		has_one = target
    )]
    pub payment: Account<'info, Payment>,
    #[account(
        mut,
        seeds = [ b"wallet".as_ref(), &wallet_id.to_le_bytes().as_ref() ],
        bump = wallet.bump
    )]
    pub wallet: Account<'info, Wallet>,
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut)]
    pub target: UncheckedAccount<'info>
}

#[account]
#[derive(Default)]
pub struct Wallet {
    owner: Pubkey,
    total_payments: u128,
    wallet_id: u32,
    min_confirmation: u8,
    bump: u8,
    admins: Vec<Pubkey>
}

#[account]
#[derive(Default)]
pub struct Payment {
    target: Pubkey,
    payment_id: u128,
    amount: u64,
    is_executed: bool,
    bump: u8,
    confirm: Vec<Pubkey>
}

#[event]
pub struct NewWalletCreated {
    creator: Pubkey
}

#[event]
pub struct SolDeposited {
    wallet: Pubkey,
    from: Pubkey,
    amount: f64
}

#[event]
pub struct PaymentExecuted {
    wallet: Pubkey,
    payment: Pubkey,
    executer: Pubkey
}

#[error_code]
pub enum Errors {
    #[msg("Admins count == 0 !")]
    AdminZeroCount,
    #[msg("Max admins count == 5 .")]
    AdminMaxCount,
    #[msg("Confirmations count == 0 !")]
    ConfirmationZeroCount,
    #[msg("Confirmations count > Owner + Admins count !")]
    ConfirmationMaxCount,
    #[msg("Invalid access.")]
    InvalidAccess,
    #[msg("Zero sol amount!")]
    ZeroSOL,
    #[msg("Insufficeint wallet balance.")]
    InsufficeintWalletBalance,
    #[msg("Payment already executed!")]
    PaymentAlreadyExecuted,
    #[msg("You already voted!")]
    DuplicateVote,
    #[msg("You didn't confirmed!")]
    NotVotedBefore,
    #[msg("You cannot execute the payment.")]
    YouCannotExecute,
    #[msg("Confirmations are low.")]
    LowConfirmations
}
