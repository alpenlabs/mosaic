use object_store::aws::{AmazonS3Builder, AmazonS3ConfigKey};

pub(crate) fn configured_builder(
    access_key_id: Option<&str>,
    secret_access_key: Option<&str>,
    session_token: Option<&str>,
    endpoint: Option<&str>,
) -> AmazonS3Builder {
    // Static config must not inherit an unrelated AWS_SESSION_TOKEN or endpoint.
    // Without configured keys, retain from_env() for IRSA and container credentials.
    let mut builder = if access_key_id.is_some() && secret_access_key.is_some() {
        AmazonS3Builder::new()
    } else {
        AmazonS3Builder::from_env()
    };

    if let Some(access_key_id) = access_key_id {
        builder = builder.with_access_key_id(access_key_id);
    }
    if let Some(secret_access_key) = secret_access_key {
        builder = builder.with_secret_access_key(secret_access_key);
    }
    if let Some(session_token) = session_token {
        builder = builder.with_token(session_token);
    }
    if let Some(endpoint) = endpoint {
        // S3Endpoint takes priority over Endpoint inside object_store. Set the
        // same field as AWS_ENDPOINT_URL_S3 so that the explicit config wins.
        builder = builder.with_config(AmazonS3ConfigKey::S3Endpoint, endpoint);
    }
    builder
}

#[cfg(test)]
mod tests {
    use std::{process::Command, time::Duration};

    use object_store::{path::Path, signer::Signer};

    use super::*;

    // Mutating the process environment would race other parallel tests. Run
    // each environment-sensitive assertion in its own clean child instead.
    fn in_child(test: &str, env: &[(&str, &str)]) -> bool {
        if std::env::var("MOSAIC_S3_TEST_CHILD").as_deref() == Ok(test) {
            return true;
        }
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", test, "--nocapture"])
            .env_clear()
            .env("MOSAIC_S3_TEST_CHILD", test)
            .envs(env.iter().copied())
            .output()
            .expect("run isolated S3 test");
        assert!(
            output.status.success(),
            "isolated test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }

    fn check_signed_request(
        builder: AmazonS3Builder,
        key: &str,
        secret: &str,
        token: Option<&str>,
        host: &str,
    ) {
        let store = builder
            .with_bucket_name("mosaic-test")
            .with_region("us-east-1")
            .build()
            .expect("build S3 store without a request");
        tokio::runtime::Runtime::new()
            .expect("test runtime")
            .block_on(async {
                let credentials = store
                    .credentials()
                    .get_credential()
                    .await
                    .expect("static keys");
                assert_eq!(credentials.key_id, key);
                assert_eq!(credentials.secret_key, secret);
                assert_eq!(credentials.token.as_deref(), token);
                let url = store
                    .signed_url(
                        "GET".parse().expect("HTTP method"),
                        &Path::from("table"),
                        Duration::from_secs(60),
                    )
                    .await
                    .expect("sign request locally");
                assert_eq!(url.host_str(), Some(host));
                let query: Vec<_> = url.query_pairs().collect();
                assert!(query.iter().any(|(name, value)| {
                    name == "X-Amz-Credential" && value.starts_with(&format!("{key}/"))
                }));
                assert_eq!(
                    query
                        .iter()
                        .find(|(name, _)| name == "X-Amz-Security-Token")
                        .map(|(_, value)| value.as_ref()),
                    token
                );
            });
    }

    #[test]
    fn static_credentials_ignore_ambient_token() {
        if !in_child(
            "s3::tests::static_credentials_ignore_ambient_token",
            &[
                ("AWS_ACCESS_KEY_ID", "ambient-key"),
                ("AWS_SECRET_ACCESS_KEY", "ambient-secret"),
                ("AWS_SESSION_TOKEN", "stale-token"),
                ("AWS_ENDPOINT_URL_S3", "https://ambient.invalid"),
            ],
        ) {
            return;
        }
        let builder = configured_builder(
            Some("config-key"),
            Some("config-secret"),
            None,
            Some("https://configured.invalid"),
        );
        assert_eq!(builder.get_config_value(&AmazonS3ConfigKey::Token), None);
        check_signed_request(
            builder,
            "config-key",
            "config-secret",
            None,
            "configured.invalid",
        );
    }

    #[test]
    fn configured_endpoint_overrides_s3_environment() {
        if !in_child(
            "s3::tests::configured_endpoint_overrides_s3_environment",
            &[
                ("AWS_ACCESS_KEY_ID", "ambient-key"),
                ("AWS_SECRET_ACCESS_KEY", "ambient-secret"),
                ("AWS_ENDPOINT_URL_S3", "https://ambient.invalid"),
            ],
        ) {
            return;
        }
        // Keep the environment credential path while overriding its endpoint.
        let builder = configured_builder(None, None, None, Some("https://configured.invalid"));
        check_signed_request(
            builder,
            "ambient-key",
            "ambient-secret",
            None,
            "configured.invalid",
        );
    }

    #[test]
    fn explicit_session_token_overrides_environment() {
        if !in_child(
            "s3::tests::explicit_session_token_overrides_environment",
            &[("AWS_SESSION_TOKEN", "stale-token")],
        ) {
            return;
        }
        let builder = configured_builder(
            Some("config-key"),
            Some("config-secret"),
            Some("config-token"),
            Some("https://configured.invalid"),
        );
        check_signed_request(
            builder,
            "config-key",
            "config-secret",
            Some("config-token"),
            "configured.invalid",
        );
    }

    #[test]
    fn omitted_static_config_preserves_environment_credentials_and_endpoint() {
        if !in_child(
            "s3::tests::omitted_static_config_preserves_environment_credentials_and_endpoint",
            &[
                ("AWS_ACCESS_KEY_ID", "ambient-key"),
                ("AWS_SECRET_ACCESS_KEY", "ambient-secret"),
                ("AWS_SESSION_TOKEN", "ambient-token"),
                ("AWS_ENDPOINT_URL_S3", "https://ambient.invalid"),
            ],
        ) {
            return;
        }
        check_signed_request(
            configured_builder(None, None, None, None),
            "ambient-key",
            "ambient-secret",
            Some("ambient-token"),
            "ambient.invalid",
        );
    }

    #[test]
    fn static_credentials_do_not_inherit_an_omitted_endpoint() {
        if !in_child(
            "s3::tests::static_credentials_do_not_inherit_an_omitted_endpoint",
            &[
                ("AWS_ENDPOINT_URL_S3", "https://ambient.invalid"),
                ("AWS_SESSION_TOKEN", "stale-token"),
            ],
        ) {
            return;
        }
        let builder = configured_builder(Some("config-key"), Some("config-secret"), None, None);
        assert_eq!(
            builder.get_config_value(&AmazonS3ConfigKey::S3Endpoint),
            None
        );
        check_signed_request(
            builder,
            "config-key",
            "config-secret",
            None,
            "s3.us-east-1.amazonaws.com",
        );
    }

    #[test]
    fn irsa_configuration_is_preserved_without_static_keys() {
        if !in_child(
            "s3::tests::irsa_configuration_is_preserved_without_static_keys",
            &[
                ("AWS_WEB_IDENTITY_TOKEN_FILE", "/synthetic/token"),
                ("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/mosaic-test"),
                ("AWS_ROLE_SESSION_NAME", "mosaic-test"),
                ("AWS_ENDPOINT_URL_STS", "https://sts.invalid"),
            ],
        ) {
            return;
        }
        let builder = configured_builder(None, None, None, Some("https://configured.invalid"));
        for (key, value) in [
            (AmazonS3ConfigKey::WebIdentityTokenFile, "/synthetic/token"),
            (
                AmazonS3ConfigKey::RoleArn,
                "arn:aws:iam::123456789012:role/mosaic-test",
            ),
            (AmazonS3ConfigKey::RoleSessionName, "mosaic-test"),
            (AmazonS3ConfigKey::StsEndpoint, "https://sts.invalid"),
        ] {
            assert_eq!(builder.get_config_value(&key).as_deref(), Some(value));
        }
        assert_eq!(
            builder.get_config_value(&AmazonS3ConfigKey::AccessKeyId),
            None
        );
        // Do not resolve these synthetic IRSA credentials or contact STS/IMDS.
    }
}
