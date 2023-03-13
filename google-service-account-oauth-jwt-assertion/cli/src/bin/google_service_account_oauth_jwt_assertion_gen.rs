/*
cargo run -p google-service-account-oauth-jwt-assertion-cli --bin google_service_account_oauth_jwt_assertion_gen -- '/path/project-123456-123456789012.json' 'https://www.googleapis.com/auth/androidpublisher'
Or
cargo install google-service-account-oauth-jwt-assertion-cli
google_service_account_oauth_jwt_assertion_gen '/path/project-123456-123456789012.json' 'https://www.googleapis.com/auth/androidpublisher'
*/

use std::{env, fs};

use google_service_account_oauth_jwt_assertion::create_from_service_account_json_key;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service_account_json_key_path = env::args().nth(1).unwrap();
    let scopes = env::args().nth(2).unwrap();

    let service_account_json_key_bytes = fs::read(service_account_json_key_path)?;

    let client_secret = create_from_service_account_json_key(
        service_account_json_key_bytes,
        scopes
            .split(' ')
            .map(|x| x.into())
            .collect::<Vec<_>>()
            .as_ref(),
    )?;

    println!("{client_secret}");

    Ok(())
}
