#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use centrum_primitives::Account;
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::pallet_prelude::ConstU32;
use frame_support::{dispatch::DispatchResult, IterableStorageDoubleMap};
use frame_system::ensure_signed;
use scale_info::TypeInfo;
use sp_runtime::{AccountId32, BoundedVec};

// Re-export pallet items so that they can be accessed from the crate namespace.
pub use pallet::*;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub enum Permissions {
    Everything,
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config<AccountId = centrum_primitives::Account> {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    pub(super) type NamedAccountSigners<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        BoundedVec<u8, ConstU32<32>>,
        Twox64Concat,
        AccountId32,
        Permissions,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        AccountCreated {
            name: Vec<u8>,
            signer: AccountId32,
        },

        SignerAdded {
            account: Vec<u8>,
            signer: AccountId32,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        NameTooLong,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(1)]
        pub fn create_account(
            origin: OriginFor<T>,
            name: Vec<u8>,
            public_key: AccountId32,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            let name: BoundedVec<u8, ConstU32<32>> =
                name.try_into().map_err(|_| Error::<T>::NameTooLong)?;

            NamedAccountSigners::<T>::insert(
                name.clone(),
                public_key.clone(),
                Permissions::Everything,
            );

            Self::deposit_event(Event::<T>::AccountCreated {
                name: name.into_inner(),
                signer: public_key,
            });

            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(1)]
        pub fn add_signer(origin: OriginFor<T>, public_key: AccountId32) -> DispatchResult {
            let account = ensure_signed(origin)?;
            let name = ensure_named(account)?;

            NamedAccountSigners::<T>::insert(
                name.clone(),
                public_key.clone(),
                Permissions::Everything,
            );

            Self::deposit_event(Event::<T>::SignerAdded {
                account: name.into_inner(),
                signer: public_key,
            });

            Ok(())
        }
    }
}

#[allow(dead_code)]
impl<T: Config> Pallet<T> {
    pub fn get_signers_for_account(name: BoundedVec<u8, ConstU32<32>>) -> Vec<AccountId32> {
        NamedAccountSigners::<T>::iter_key_prefix(name).collect()
    }

    pub fn is_signer_for_account(
        name: BoundedVec<u8, ConstU32<32>>,
        public_key: AccountId32,
    ) -> bool {
        NamedAccountSigners::<T>::contains_key(name, public_key)
    }
}

pub fn ensure_named(
    account: Account,
) -> Result<BoundedVec<u8, ConstU32<32>>, sp_runtime::traits::BadOrigin> {
    if let Account::Named(name) = account {
        Ok(name)
    } else {
        Err(sp_runtime::traits::BadOrigin)
    }
}
