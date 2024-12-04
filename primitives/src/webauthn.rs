use codec::{Decode, Encode, MaxEncodedLen};
use p256::ecdsa::signature::Verifier;
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_core::sha2_256;
use sp_std::vec::Vec;

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Encode, Decode, TypeInfo)]
struct ClientData {
    r#type: Vec<u8>,
    challenge: Vec<u8>,
    origin: Vec<u8>,
}

#[derive(Eq, PartialEq, Clone, Encode, Decode, Debug, TypeInfo, Serialize, Deserialize)]
pub struct WebAuthnData {
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    client_data: ClientData,
    signed_bytes: Vec<u8>,
    challenge: Vec<u8>,
}

impl WebAuthnData {
    pub fn challenge(&self) -> Vec<u8> {
        self.challenge.clone()
    }
}

impl TryFrom<&WebAuthnSignature> for WebAuthnData {
    type Error = ();

    fn try_from(signature: &WebAuthnSignature) -> Result<Self, Self::Error> {
        let client_data: ClientData =
            match serde_json::from_slice(&signature.client_data_json.0[..]) {
                Ok(client_data) => client_data,
                // Err(err) => return Err(format!("ClientDataJSON parsing failed with: {}", err)),
                Err(err) => return Err(()),
            };

        let challenge = match base64::decode_config(&client_data.challenge, base64::URL_SAFE_NO_PAD)
        {
            Ok(challenge) => challenge,
            // Err(err) => return Err(format!("Challenge base64url parsing failed with: {}", err)),
            Err(err) => return Err(()),
        };

        let mut signed_bytes = signature.authenticator_data.0.clone();
        signed_bytes.append(&mut sha2_256(&signature.client_data_json.0.clone()[..]).to_vec());

        Ok(WebAuthnData {
            client_data_json: signature.client_data_json.0.clone(),
            authenticator_data: signature.authenticator_data.0.clone(),
            client_data,
            signed_bytes,
            challenge,
        })
    }
}

#[derive(
    Clone, Eq, PartialEq, Hash, Default, Deserialize, Serialize, Debug, Encode, Decode, TypeInfo,
)]
pub struct Blob(#[serde(with = "serde_bytes")] pub Vec<u8>);

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize, Encode, Decode, TypeInfo)]
pub struct WebAuthnSignature {
    authenticator_data: Blob,
    client_data_json: Blob,
    signature: Blob,
}

// TODO: Implement this properly.
impl MaxEncodedLen for WebAuthnSignature {
    fn max_encoded_len() -> usize {
        usize::MAX
    }
}

impl WebAuthnSignature {
    pub fn new(authenticator_data: Blob, client_data_json: Blob, signature: Blob) -> Self {
        Self {
            authenticator_data,
            client_data_json,
            signature,
        }
    }

    pub fn authenticator_data(&self) -> Blob {
        self.authenticator_data.clone()
    }

    pub fn client_data_json(&self) -> Blob {
        self.client_data_json.clone()
    }

    pub fn signature(&self) -> Blob {
        self.signature.clone()
    }

    pub fn verify(&self, tx_payload: &[u8], public_key: [u8; 32]) -> Result<(), ()> {
        let basic_sig = p256_signature_from_der(&self.signature().0)
            //.map_err(|e| format!("Failed to parse EcdsaP256 signature: {}", e))?;
            .map_err(|e| ())?;

        let data = match WebAuthnData::try_from(self) {
            Ok(data) => data,
            Err(err) => {
                // return Err(format!("WebAuthn data creation failed: {}", err));
                return Err(());
            }
        };

        p256_verify_signature_with_pubkey(&basic_sig.clone(), &data, public_key).map_err(|e| {
            // format!(
            //     "Verifying signature failed. signature: {:?}; data: {:?}; public_key: {:?}. Error: {}",
            //     basic_sig, data.clone(), public_key, e
            // )
            ()
        })?;

        // The challenge in the webauthn envelope must match signed bytes.
        if &data.challenge() != tx_payload {
            // Err(format!(
            //     "Challenge in webauthn is {:?} while it is expected to be {:?}",
            //     data.challenge(),
            //     tx_payload,
            // ))
            Err(())
        } else {
            Ok(())
        }
    }
}

impl TryFrom<&[u8]> for WebAuthnSignature {
    type Error = ();

    fn try_from(blob: &[u8]) -> Result<Self, Self::Error> {
        let signature: WebAuthnSignature = serde_cbor::from_slice(blob)
            // .map_err(|err| format!("Signature CBOR parsing failed with: {}", err))?;
            .map_err(|e| ())?;
        Ok(signature)
    }
}

pub fn p256_signature_from_der(sig_der: &[u8]) -> Result<[u8; 64], ()> {
    let sig = p256::ecdsa::Signature::from_der(sig_der)
        //.map_err(|e| e.to_string())?;
        .map_err(|e| ())?;

    let sig_bytes: [u8; 64] = sig.to_bytes().into();
    Ok(sig_bytes)
}

pub fn p256_verify_signature_with_pubkey(
    sig: &[u8; 64],
    data: &WebAuthnData,
    pubkey: [u8; 32],
) -> Result<(), ()> {
    let signature = p256::ecdsa::Signature::from_bytes(sig[..64].into()).unwrap();

    let pubkey = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey)
        //.map_err(|e| e.to_string())?;
        .map_err(|e| ())?;

    pubkey
        .verify(&data.signed_bytes, &signature)
        //.map_err(|e| e.to_string())
        .map_err(|e| ())
}
