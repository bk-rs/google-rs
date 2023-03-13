//! [Doc](https://developers.google.com/identity/protocols/oauth2/service-account#httprest)

use core::time::Duration;

use chrono::{serde::ts_seconds, DateTime, Duration as ChronoDuration, Utc};
use jsonwebtoken::{encode, errors::Error as JsonwebtokenError, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

pub const AUDIENCE: &str = "https://oauth2.googleapis.com/token";
// 1 hour
pub const EXPIRATION_TIME_DURATION_SECONDS_MAX: u64 = 3600;

//
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Claims {
    pub iss: String,
    pub scope: String,
    pub aud: String,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
}

pub fn create(
    private_key_bytes: impl AsRef<[u8]>,
    client_email: impl AsRef<str>,
    scopes: &[String],
    issued_at: impl Into<Option<DateTime<Utc>>>,
    expiration_time_dur: impl Into<Option<Duration>>,
    sub: impl Into<Option<String>>,
) -> Result<String, CreateError> {
    let private_key_bytes = private_key_bytes.as_ref();

    let key =
        EncodingKey::from_rsa_pem(private_key_bytes).map_err(CreateError::MakeEncodingKeyFailed)?;

    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".into());

    let issued_at = issued_at.into().unwrap_or_else(Utc::now);
    let mut expiration_time_dur = expiration_time_dur
        .into()
        .unwrap_or_else(|| Duration::from_secs(EXPIRATION_TIME_DURATION_SECONDS_MAX));
    if expiration_time_dur.as_secs() > EXPIRATION_TIME_DURATION_SECONDS_MAX {
        expiration_time_dur = Duration::from_secs(EXPIRATION_TIME_DURATION_SECONDS_MAX);
    }
    let expiration_time = issued_at + ChronoDuration::seconds(expiration_time_dur.as_secs() as i64);

    let claims = Claims {
        iss: client_email.as_ref().into(),
        scope: scopes.join(" "),
        aud: AUDIENCE.into(),
        exp: expiration_time,
        iat: issued_at,
        sub: sub.into(),
    };

    let token = encode(&header, &claims, &key).map_err(CreateError::EncodeFailed)?;

    Ok(token.as_str().into())
}

#[cfg(feature = "google-service-account-json-key")]
pub fn create_from_service_account_json_key(
    json: impl AsRef<str>,
    scopes: &[String],
) -> Result<String, CreateError> {
    use google_service_account_json_key::Key;

    let json = json.as_ref();

    let key = json
        .parse::<Key>()
        .map_err(|err| CreateError::ParseServiceAccountJsonKeyFailed(err.to_string()))?;

    create(
        &key.private_key,
        &key.client_email,
        scopes,
        None,
        None,
        None,
    )
}

//
#[derive(Debug)]
pub enum CreateError {
    MakeEncodingKeyFailed(JsonwebtokenError),
    EncodeFailed(JsonwebtokenError),
    ParseServiceAccountJsonKeyFailed(String),
}
impl core::fmt::Display for CreateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CreateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_for_pem() {
        const PEM_PRIVATE_KEY : &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLs9M9cBICRquC\nARPxcKVzToxE6zeSfDWhBjjqzk/zoiS9NOzR538lGxU8qE1kc+ZH0+6QWUsQ4ZwB\nzJUD/OFp5QvhD89xjAThoNOKc3kj6l+siWbdAKwNVOdTOpXwpomlwOlMp/t9Dpia\n6YIcWK+OuTW9XlPHsl9BJnk/WgDZFeqsQ4PyFGW/o+UrqzCpqHVmLyiUb6SIGIzq\nFiU61zvhBkO2mDnQVqMELFhDzBwky8T6A7jnh3pZBphs4v/sUFHJrk/ozcgnDXXK\nAqQwvu3jagc6FZvrNyCSF2yD41WwB9Su78ZnX4BPfKfc57pJyU2LHh9dtOqXZuq3\nvq2ivT7RAgMBAAECggEABlmdvS2QMif30r6r23vyfGy3bLKUcemTVmi2P4Oc9HBa\nitdqhoSb7xEwEUsB1p7ST+zoY/GUqHsP/PJettgcQsvUGfj/M3/06v+zeH5vCVKW\nFu/VmBAcTPIXn/2UjQL0CYnA/BXEfjqFQVcEKlQNbPqTFUsqe3AxDfvgDbyFiD7b\nZYq83mFLah+Qfrev8BGUvDBS2F68Rf8nxOMxEprMRCwOeevkAHSBESbIV6hs79es\noM6+mS3Mr8dzLRjAWl9H2Xy5EM2wS4esEAqBgjlFhepIJ9/adF2VO4BqK+addrdr\ndN59fuAGAj+pxWdoxDtUuXSx+sd8ZiGMnjIQklzRfQKBgQDyfwfTwJF/S2kuwVhW\nnjm5uvpscj41UVdTuJgdg8fqZ27AO1EBjINkKR718NicNSNAMmDrl8wVje48JphS\nPxfr7qG5q9nR7qPhjOFZosTFwyrdG1YjbxOFb5oHWAzILbFfCOin0Bs6xmpPGq7a\n7N5OKE3tEY0tU0W/I2Yu05LfcwKBgQDXC8J3Si0XZXIlRpaveKJiOqyF6hvNGgGI\n4e2OsfBCMP/P68HHUiwFok67XIDlRmsvYtfhfswThcir5pErV868uMTXtQbe4tUk\ngHkv5fgu/pBamAr9KA3aZ1O1k/56zAg/OsXKFsNYrFLgdOLEF1xnqs/EGBhN6sr9\nv93ZmjzPqwKBgQC6uGOvgiTGbqukC85Yi+cJA1dWb7VE2sgyN/4xI8qozFH0BPiA\nB9EYK62iVHyF80icYu5MGgtUQYBCorlBA0IJMisnS5MiWe2ofBD9Mx7u5DO6IxV1\nnU7bvS5OH1dgQAbGlZaHuO9ul18+X95pxl/6sIAoXg5l6yvWXIyO2+zIzwKBgQC0\nc4fBthrUcSoxoWQ85ovMxdOTo/mkSFhVVtCTVzl3McrX3MuEyK1sJODQVDVNL6Qt\n5VGmRVJWZ4MWzKmwp0QyFRIIuD2Ftu6IbM5EpUN3m+HiQ4elG4FUbjROQFvhC2k4\nNcdXZ3aQ6Dm7ZBoN1lSSIUGrGVT7vTSNbf1p5gV1dQKBgBRQW6DSrLJOasuGEwOx\nhHkZql4OyGllGf0iqnGMB/kBzuRKsWIl5cGaEa0wNwayXvsukrNJhuMPj5nWNPJn\nTzmaFmwZrHP498Tn46dzs2y8q4V4Wgezs9r8FNU77jegTl2gB1Kq7o+bKLr5PCkW\nPpBjGLz11+feMWsX4R/MGCuA\n-----END PRIVATE KEY-----\n";

        let assertion = create(
            PEM_PRIVATE_KEY,
            "761326798069-r5mljlln1rd4lrbhg75efgigp36m78j5@developer.gserviceaccount.com",
            &["https://www.googleapis.com/auth/devstorage.read_only".into()],
            "2022-06-06T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
            Duration::from_secs(3600),
            None,
        )
        .unwrap();

        println!("{assertion}");
        let mut split = assertion.split('.');
        assert_eq!(
            split.next().unwrap(),
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"
        );
        assert_eq!(split.next().unwrap() , "eyJpc3MiOiI3NjEzMjY3OTgwNjktcjVtbGpsbG4xcmQ0bHJiaGc3NWVmZ2lncDM2bTc4ajVAZGV2ZWxvcGVyLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJzY29wZSI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL2F1dGgvZGV2c3RvcmFnZS5yZWFkX29ubHkiLCJhdWQiOiJodHRwczovL29hdXRoMi5nb29nbGVhcGlzLmNvbS90b2tlbiIsImV4cCI6MTY1NDQ3NzIwMCwiaWF0IjoxNjU0NDczNjAwfQ");
        split.next();
        assert!(split.next().is_none());
    }
}
