pub use google_service_account_oauth_jwt_assertion;
pub use oauth2_client;
pub use oauth2_google;

//
pub mod single;

pub type ResponseSuccessfulBody =
    oauth2_client::oauth2_core::jwt_authorization_grant::access_token_response::SuccessfulBody<
        oauth2_google::GoogleScope,
    >;
pub type IssuedAt = std::time::SystemTime;
