mod conv;
mod poly;
mod shamir;

use blst::BLST_ERROR;

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// An error was raised from the Supranational BLST BLS library.
    BlstError(BLST_ERROR),
    InvalidInput,
    InvalidThresholdParameters,
    NotEnoughShares,
    DuplicateShares,
    UninitializedPoly,
}

pub use poly::*;
pub use shamir::*;
