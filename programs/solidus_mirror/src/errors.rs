use anchor_lang::prelude::*;

/// The EVM contract's error names, so a failure reads the same on every destination.
#[error_code]
pub enum MirrorError {
    #[msg("message does not decode")]
    CodecError,
    #[msg("message is not the next in sequence")]
    OutOfSequence,
    #[msg("fewer signatures than the threshold")]
    NotEnoughSignatures,
    #[msg("signature s value is in the upper half of the curve order")]
    HighS,
    #[msg("signature does not recover")]
    BadSignature,
    #[msg("signers must be strictly ascending")]
    SignersOutOfOrder,
    #[msg("signer is not a configured validator")]
    UnknownSigner,
    #[msg("threshold must be between 1 and the number of validators")]
    BadThreshold,
    #[msg("validator listed twice")]
    DuplicateValidator,
    #[msg("zero address is not a validator")]
    ZeroValidator,
    #[msg("too many validators")]
    TooManyValidators,
    #[msg("only the program's upgrade authority may initialise the mirror")]
    NotUpgradeAuthority,
    #[msg("an account passed for this message is not the PDA its body derives")]
    WrongAccount,
    #[msg("an account the message needs was not passed")]
    MissingAccount,
    /// Appended last, so the error codes before it do not move.
    #[msg("this mirror does not apply token messages")]
    UnsupportedKind,
}
