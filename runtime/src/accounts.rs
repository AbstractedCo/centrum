use super::Runtime;
use codec::{Decode, Encode};
use frame_support::pallet_prelude::MaxEncodedLen;
use scale_info::TypeInfo;
use sp_core::ConstU32;
use sp_runtime::BoundedVec;
use sp_runtime::Vec;

pub use centrum_primitives::Account;

#[derive(Clone, TypeInfo, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, MaxEncodedLen, Debug)]
pub struct SignersGetter;

impl centrum_primitives::GetNamedAccountSigners for SignersGetter {
    fn get_named_account_signers(
        name: BoundedVec<u8, ConstU32<32>>,
    ) -> Vec<sp_runtime::AccountId32> {
        pallet_accounts::Pallet::<Runtime>::get_signers_for_account(name)
    }

    fn is_signer_for_named_account(
        name: BoundedVec<u8, ConstU32<32>>,
        public_key: sp_runtime::AccountId32,
    ) -> bool {
        pallet_accounts::Pallet::<Runtime>::is_signer_for_account(name, public_key)
    }
}
