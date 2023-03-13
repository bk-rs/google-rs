## Dev

```
cargo clippy --all-features --tests --examples -- -D clippy::all
cargo +nightly clippy --all-features --tests --examples -- -D clippy::all

cargo fmt -- --check

cargo test-all-features -- --nocapture
```

## Publish order

google-service-account-json-key

google-service-account-oauth-jwt-assertion

google-service-account-oauth-jwt-assertion/cli
