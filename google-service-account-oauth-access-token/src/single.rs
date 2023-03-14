use core::{future::Future, pin::Pin, time::Duration};
use std::{sync::Arc, time::SystemTime};

use arc_swap::ArcSwap;
use async_sleep::{sleep, timeout, Sleepble};
use google_service_account_oauth_jwt_assertion::{
    create_from_service_account_json_key as assertion_create_from_service_account_json_key,
    CreateError as AssertionCreateError, EXPIRATION_TIME_DURATION_SECONDS_MAX,
};
use http_api_isahc_client::IsahcClient;
use oauth2_client::jwt_authorization_grant::{Flow, FlowExecuteError};
use oauth2_google::{GoogleProviderForServerToServerApps, GoogleScope};
use once_cell::sync::Lazy;

use crate::{IssuedAt, ResponseSuccessfulBody};

//
const ASSERTION_EXP_DUR: Duration = Duration::from_secs(EXPIRATION_TIME_DURATION_SECONDS_MAX);

//
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Manager;

impl Manager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, body: ResponseSuccessfulBody, issued_at: SystemTime) {
        let storage = AccessTokenStorage(Some((body, issued_at)));
        ACCESS_TOKEN_STORAGE.store(Arc::new(storage));
    }

    pub fn clear(&self) {
        let storage = AccessTokenStorage(None);
        ACCESS_TOKEN_STORAGE.store(Arc::new(storage));
    }

    pub fn get_value(&self) -> Option<String> {
        ACCESS_TOKEN_STORAGE
            .load()
            .0
            .as_ref()
            .map(|(body, _)| body.access_token.as_str().into())
    }

    pub async fn request(
        &self,
        service_account_json_key_bytes: impl AsRef<[u8]>,
        scopes: &[GoogleScope],
    ) -> Result<(ResponseSuccessfulBody, IssuedAt), ManagerRequestError> {
        let assertion = match get_not_expired_assertion() {
            Some(x) => x,
            None => {
                let issued_at = SystemTime::now();
                let assertion = assertion_create_from_service_account_json_key(
                    service_account_json_key_bytes,
                    scopes
                        .iter()
                        .map(|x| x.to_string())
                        .collect::<Vec<_>>()
                        .as_ref(),
                )
                .map_err(ManagerRequestError::AssertionCreateFailed)?;

                let storage = AssertionStorage(Some((assertion.to_owned(), issued_at)));
                ASSERTION_STORAGE.store(Arc::new(storage));

                assertion
            }
        };

        let flow = Flow::new(ACCESS_TOKEN_REQUEST_HTTP_CLIENT.to_owned());
        let provider = GoogleProviderForServerToServerApps::new(assertion)
            .map_err(|err| ManagerRequestError::OauthProviderMakeFailed(err.to_string()))?;

        let issued_at = SystemTime::now();
        let body = flow
            .execute(&provider, None)
            .await
            .map_err(ManagerRequestError::AccessTokenRequestFailed)?;

        let storage = AccessTokenStorage(Some((body.to_owned(), issued_at)));
        ACCESS_TOKEN_STORAGE.store(Arc::new(storage));

        Ok((body, issued_at))
    }

    pub async fn run<SLEEP, RequestCb>(
        &self,
        service_account_json_key_bytes: impl AsRef<[u8]>,
        scopes: &[GoogleScope],
        request_callback: RequestCb,
    ) where
        SLEEP: Sleepble,
        RequestCb: Fn(
                Result<(ResponseSuccessfulBody, IssuedAt), ManagerRequestError>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>
            + Send
            + Sync,
    {
        let service_account_json_key_bytes = service_account_json_key_bytes.as_ref();

        loop {
            if get_not_expired_access_token().is_some() {
                sleep::<SLEEP>(Duration::from_secs(60 * 3)).await;
                continue;
            }

            match self.request(service_account_json_key_bytes, scopes).await {
                Ok((body, issued_at)) => {
                    let _ = timeout::<SLEEP, _>(
                        Duration::from_secs(6),
                        request_callback(Ok((body, issued_at))),
                    )
                    .await;

                    sleep::<SLEEP>(Duration::from_secs(60 * 3)).await;
                    continue;
                }
                Err(err) => {
                    let _ = timeout::<SLEEP, _>(Duration::from_secs(3), request_callback(Err(err)))
                        .await;

                    sleep::<SLEEP>(Duration::from_secs(5)).await;
                    continue;
                }
            }
        }
    }
}

//
#[derive(Debug)]
pub enum ManagerRequestError {
    AssertionCreateFailed(AssertionCreateError),
    OauthProviderMakeFailed(String),
    AccessTokenRequestFailed(FlowExecuteError),
}

impl core::fmt::Display for ManagerRequestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ManagerRequestError {}

//
//
//
static ASSERTION_STORAGE: Lazy<ArcSwap<AssertionStorage>> =
    Lazy::new(|| ArcSwap::from(Arc::new(AssertionStorage::default())));

#[derive(Debug, Clone, Default)]
struct AssertionStorage(Option<(String, IssuedAt)>);

fn get_not_expired_assertion() -> Option<String> {
    if let Some((assertion, issued_at)) = ASSERTION_STORAGE.load().0.as_ref() {
        if let Ok(dur) = SystemTime::now().duration_since(*issued_at) {
            if dur < (ASSERTION_EXP_DUR - Duration::from_secs(60 * 10)) {
                return Some(assertion.to_owned());
            }
        }
    }
    None
}

//
//
//
static ACCESS_TOKEN_STORAGE: Lazy<ArcSwap<AccessTokenStorage>> =
    Lazy::new(|| ArcSwap::from(Arc::new(AccessTokenStorage::default())));

#[derive(Debug, Clone, Default)]
struct AccessTokenStorage(Option<(ResponseSuccessfulBody, IssuedAt)>);

fn get_not_expired_access_token() -> Option<ResponseSuccessfulBody> {
    if let Some((body, issued_at)) = ACCESS_TOKEN_STORAGE.load().0.as_ref() {
        if let Some(body_expires_in) = body.expires_in {
            if let Ok(dur) = SystemTime::now().duration_since(*issued_at) {
                if dur.as_secs() < (body_expires_in as u64 - 60 * 5) {
                    return Some(body.to_owned());
                }
            }
        } else {
            return Some(body.to_owned());
        }
    }
    None
}

//
//
//
static ACCESS_TOKEN_REQUEST_HTTP_CLIENT: Lazy<IsahcClient> =
    Lazy::new(|| IsahcClient::new().expect(""));

#[cfg(test)]
mod example_tokio {
    use super::*;

    use async_sleep::impl_tokio::Sleep;

    //
    #[derive(Debug, Clone)]
    pub struct MyManager {
        inner: Manager,
        ctx: Arc<()>,
    }

    impl MyManager {
        pub async fn new(ctx: Arc<()>) -> Self {
            let inner = Manager::new();

            // TODO, read cache then set
            // inner.set(body, issued_at);

            Self { inner, ctx }
        }

        pub fn get_value(&self) -> Option<String> {
            self.inner.get_value()
        }

        pub async fn run(
            &self,
            service_account_json_key_bytes: impl AsRef<[u8]>,
            scopes: &[GoogleScope],
        ) {
            self.inner
                .run::<Sleep, _>(service_account_json_key_bytes, scopes, |ret| {
                    Box::pin({
                        let _ctx = self.ctx.clone();

                        async move {
                            match ret {
                                Ok((_body, _issued_at)) => {
                                    // TODO, write cache
                                }
                                Err(_err) => {
                                    // TODO, log
                                }
                            }
                        }
                    })
                })
                .await
        }
    }

    #[tokio::test]
    async fn simple() {
        let ctx = Arc::new(());

        {
            let ctx = ctx.clone();
            let mgr = MyManager::new(ctx).await;

            tokio::spawn(async move {
                mgr.run(
                    r#"
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
                    "#,
                    &[GoogleScope::AndroidPublisher]
                )
                .await
            });
        }

        {
            let ctx = ctx.clone();
            let mgr = MyManager::new(ctx).await;

            mgr.get_value();
        }
    }
}
