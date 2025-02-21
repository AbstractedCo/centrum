#![cfg_attr(not(feature = "std"), no_std)]
#![feature(impl_trait_in_assoc_type)]

mod webauthn;

use core::marker::PhantomData;

use codec::{Decode, Encode};
use frame_support::pallet_prelude::MaxEncodedLen;
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_core::crypto::AccountId32;
use sp_core::ConstU32;
use sp_runtime::BoundedVec;
use sp_runtime::{traits::Verify, MultiSignature, MultiSigner, Vec};
use webauthn::AuthenticatorAssertionResponseRaw;

#[derive(
    Clone,
    Encode,
    Decode,
    TypeInfo,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    MaxEncodedLen,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum Account {
    PublicKey(AccountId32),
    Named(BoundedVec<u8, ConstU32<32>>),
}

#[cfg(feature = "std")]
impl std::fmt::Display for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}",
            match self {
                Self::PublicKey(p) => p.to_string(),
                Self::Named(n) => String::from_utf8_lossy(&n.clone().into_inner()).to_string(),
            }
        )
    }
}

impl From<AccountId32> for Account {
    fn from(a: AccountId32) -> Self {
        Self::PublicKey(a)
    }
}

impl From<sp_core::sr25519::Public> for Account {
    fn from(p: sp_core::sr25519::Public) -> Self {
        Self::PublicKey(p.into())
    }
}

#[derive(
    Eq, PartialEq, Ord, PartialOrd, Clone, Encode, Decode, Debug, TypeInfo, Serialize, Deserialize,
)]
pub struct CustomSigner {
    pub signer: MultiSigner,
    pub sign_for: Option<BoundedVec<u8, ConstU32<32>>>,
}

impl From<MultiSigner> for CustomSigner {
    fn from(signer: MultiSigner) -> Self {
        Self {
            signer,
            sign_for: None,
        }
    }
}

impl sp_runtime::traits::IdentifyAccount for CustomSigner {
    type AccountId = Account;

    fn into_account(self) -> Account {
        self.sign_for
            .map(|name| Account::Named(name))
            .unwrap_or(Account::PublicKey(self.signer.into_account()))
    }
}

pub trait GetNamedAccountSigners {
    fn get_named_account_signers(name: BoundedVec<u8, ConstU32<32>>) -> Vec<AccountId32OrEcdsa33>;
    fn is_signer_for_named_account(
        name: BoundedVec<u8, ConstU32<32>>,
        public_key: AccountId32OrEcdsa33,
    ) -> bool;
}

#[derive(Eq, PartialEq, Clone, Encode, Decode, Debug, TypeInfo, Serialize, Deserialize)]
pub enum MultiSignatureOrPasskeySignature {
    MultiSignature(MultiSignature),
    PasskeySignature(AuthenticatorAssertionResponseRaw),
}

#[derive(Eq, PartialEq, Clone, Encode, Decode, Debug, TypeInfo, MaxEncodedLen)]
pub enum AccountId32OrEcdsa33 {
    AccountId32(AccountId32),
    Ecdsa33([u8; 33]),
}

#[derive(Eq, PartialEq, Clone, Encode, Decode, Debug, TypeInfo)]
pub struct CustomSignature<SignersGetter> {
    pub signature: MultiSignatureOrPasskeySignature,
    pub signer: Option<AccountId32OrEcdsa33>,

    marker: PhantomData<SignersGetter>,
}

impl<SignersGetter> CustomSignature<SignersGetter> {
    pub fn new(signature: MultiSignature) -> Self {
        Self {
            signature: MultiSignatureOrPasskeySignature::MultiSignature(signature),
            signer: None,

            marker: PhantomData,
        }
    }

    pub fn new_with_signer(
        signature: MultiSignatureOrPasskeySignature,
        signer: AccountId32OrEcdsa33,
    ) -> Self {
        Self {
            signature,
            signer: Some(signer),

            marker: PhantomData,
        }
    }
}

impl<SignersGetter> Verify for CustomSignature<SignersGetter>
where
    SignersGetter: GetNamedAccountSigners,
{
    type Signer = CustomSigner;

    #[allow(unused_mut)]
    fn verify<L: sp_runtime::traits::Lazy<[u8]>>(&self, mut msg: L, signer: &Account) -> bool {
        match (signer, self.signature.clone()) {
            (Account::PublicKey(key), MultiSignatureOrPasskeySignature::MultiSignature(sig)) => {
                sig.verify(msg, key.into())
            }

            (Account::Named(name), s) => {
                if let Some(key) = self.signer.clone() {
                    // Get list of public keys attached to `name`.
                    // Search for signer in list of public keys.
                    if SignersGetter::is_signer_for_named_account(name.clone(), key.clone()) {
                        // Verify signature against found signer.
                        match (s, key) {
                            (
                                MultiSignatureOrPasskeySignature::MultiSignature(sig),
                                AccountId32OrEcdsa33::AccountId32(key),
                            ) => sig.verify(msg, &key),
                            (
                                MultiSignatureOrPasskeySignature::PasskeySignature(webauthn_data),
                                AccountId32OrEcdsa33::Ecdsa33(key),
                            ) => {
                                let encoded_point = p256::EncodedPoint::from_bytes(&key).unwrap();

                                let verifying_key =
                                    p256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point)
                                        .unwrap();

                                webauthn_data
                                    .verify(msg.get(), &verifying_key.to_sec1_bytes())
                                    .is_ok()
                            }

                            _ => false,
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }

            _ => false,
        }
    }
}
