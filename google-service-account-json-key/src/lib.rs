// https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount

use core::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_enum_str::{Deserialize_enum_str, Serialize_enum_str};
use url::Url;

//
#[derive(Deserialize_enum_str, Serialize_enum_str, Debug, Clone, PartialEq, Eq)]
pub enum KeyType {
    #[serde(rename = "service_account")]
    ServiceAccount,
    #[serde(other)]
    Other(String),
}

//
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Key {
    pub r#type: KeyType,
    pub project_id: String,
    pub private_key_id: String,
    pub private_key: String,
    pub client_email: String,
    pub client_id: String,
    pub auth_uri: Url,
    pub token_uri: Url,
    pub auth_provider_x509_cert_url: Url,
    pub client_x509_cert_url: Url,
}

impl Key {
    pub fn internal_from_str(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    pub fn internal_from_slice(v: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(v)
    }
}

impl FromStr for Key {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::internal_from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str() {
        let s = r#"
        {
            "type": "service_account",
            "project_id": "project-123456",
            "private_key_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "private_key": "-----BEGIN PRIVATE KEY-----\nx*1649\n-----END PRIVATE KEY-----\n",
            "client_email": "name@project-123456.iam.gserviceaccount.com",
            "client_id": "111111111111111111111",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/name%40project-123456.iam.gserviceaccount.com"
        }          
        "#;

        match s.parse::<Key>() {
            Ok(key) => {
                assert_eq!(key.r#type, KeyType::ServiceAccount);
                assert_eq!(key.project_id, "project-123456")
            }
            Err(err) => panic!("{err}"),
        }
    }
}
