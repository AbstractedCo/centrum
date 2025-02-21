use codec::{Decode, Encode, MaxEncodedLen};
use p256::ecdsa::signature::Verifier;
use p256::pkcs8::DecodePublicKey;
use scale_info::TypeInfo;
use serde::{de::Error, Deserialize, Serialize};
use sp_core::sha2_256;
use sp_std::vec::Vec;

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Encode, Decode, TypeInfo)]
struct ClientData {
    #[serde(deserialize_with = "decode_base64")]
    challenge: Vec<u8>,
    //  origin: Vec<u8>,
}

fn decode_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer)?;

    base64::decode_config(s, base64::URL_SAFE_NO_PAD).map_err(|e| D::Error::custom(e))
}

#[derive(Debug, Deserialize, Serialize, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
pub struct AuthenticatorAssertionResponseRaw {
    /// Raw authenticator data.
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: Vec<u8>,

    /// Signed client data.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: Vec<u8>,

    /// Signature
    pub signature: Vec<u8>,

    /// Optional userhandle.
    #[serde(rename = "userHandle")]
    pub user_handle: Option<Vec<u8>>,
}

impl AuthenticatorAssertionResponseRaw {
    pub fn get_signed_data(&self) -> Vec<u8> {
        let client_data: Vec<u8> = self.client_data_json.clone().into();
        let client_data_hash = sha2_256(&client_data);

        let auth_data: Vec<u8> = self.authenticator_data.clone().into();

        let signed_data: Vec<u8> = auth_data
            .iter()
            .chain(client_data_hash.iter())
            .copied()
            .collect();

        return signed_data;
    }

    pub fn verify(&self, tx_payload: &[u8], public_key: &[u8]) -> Result<(), ()> {
        let signature: Vec<u8> = self.signature.clone().into();

        let data = self.get_signed_data();

        p256_verify_signature_with_pubkey(&signature, &data, public_key)?;

        let client_data_json: ClientData = serde_json::from_slice(&self.client_data_json).unwrap();

        let challenge = client_data_json.challenge;

        if challenge != tx_payload {
            Err(())
        } else {
            Ok(())
        }
    }
}

pub fn p256_verify_signature_with_pubkey(sig: &[u8], data: &[u8], pubkey: &[u8]) -> Result<(), ()> {
    let signature = p256::ecdsa::Signature::from_der(sig).unwrap();

    let pubkey = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey).unwrap();

    let normalized_sig = signature.normalize_s().unwrap_or(signature);

    pubkey.verify(&data, &normalized_sig).map_err(|_| ())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use array_bytes::hex2bytes;

    use super::*;

    #[test]
    fn verify_passkey() {
        let pubkey = hex2bytes("0x0458b65f6095428f3942bb4a2cb316f1f3604f3d2cd331d9451b1a3fdc7b849e805179488b34d09284a9209a28fea7602ddf3b3800aabec945d64ac55d3e6e47a5").unwrap();

        let auth = AuthenticatorAssertionResponseRaw {
            authenticator_data:
                hex2bytes(
                    "0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000",
                )
                .unwrap(),

            client_data_json:
                hex2bytes(
                    "0x7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2241514944222c226f726967696e223a2268747470733a2f2f6c6f63616c686f73743a38303030222c2263726f73734f726967696e223a66616c73652c226f746865725f6b6579735f63616e5f62655f61646465645f68657265223a22646f206e6f7420636f6d7061726520636c69656e74446174614a534f4e20616761696e737420612074656d706c6174652e205365652068747470733a2f2f676f6f2e676c2f796162506578227d",
                )
                .unwrap(),

            signature:
             hex2bytes("0x3045022100cb29ed642aa9ec7fe4f6e7e22ab1fb8fbbd162e7f61ec469b650020418436ea902206c384157c1f0d896aff7b74196bbb42a4f1bda2c02dbc3496286df17bba3ea5b").unwrap(),

             user_handle: Some(
                  hex2bytes("0x01").unwrap()),
        };

        auth.verify(&[1, 2, 3], &pubkey).unwrap();
    }
}
