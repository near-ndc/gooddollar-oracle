use near_crypto::SecretKey;
use near_sdk::serde::de::{self, Error};
use near_sdk::serde::Deserialize;
use std::{env::VarError, str::FromStr};

#[derive(Deserialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
pub struct SignerConfig {
    pub credentials: SignerCredentials,
}

#[derive(Debug, Clone)]
pub struct SignerCredentials {
    pub seckey: SecretKey,
}

impl<'de> Deserialize<'de> for SignerCredentials {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let properties: std::collections::HashMap<String, String> =
            Deserialize::deserialize(deserializer).unwrap_or_default();

        let raw_seckey = match std::env::var("SECKEY") {
          Err(VarError::NotPresent) => properties.get("seckey").cloned(),
          Err(VarError::NotUnicode(invalid_data)) => {
              return Err(de::Error::custom(format!("Invalid SECKEY {:?}", invalid_data)))
          },
          Ok(value) => Some(value),
        }.ok_or_else(|| {
            D::Error::custom("Secret key should be provided either with SECKEY env variable or within configuration file")
        })?;

        let seckey = SecretKey::from_str(&raw_seckey).map_err(|e| {
            de::Error::custom(format!("Secret key deserialization failure. Error {e}"))
        })?;

        if !verify_secret_key(&seckey) {
            return Err(de::Error::custom("Secret key is incorrect"));
        }

        Ok(Self { seckey })
    }
}

fn verify_secret_key(seckey: &SecretKey) -> bool {
    let verification_data = "verify".as_bytes();
    let sig = seckey.sign(verification_data);
    sig.verify(verification_data, &seckey.public_key())
}
