use async_trait::async_trait;

#[async_trait]
pub trait GetAuthInfo {
    async fn run(&self) -> anyhow::Result<(String, String, String)>;
}

pub struct TokenClient<'a> {
    #[allow(dead_code)]
    getter: &'a dyn GetAuthInfo,
}

impl<'a> TokenClient<'a> {
    pub fn bulider() -> TokenClientBuilder<'a> {
        TokenClientBuilder { getter: None }
    }
}

pub struct TokenClientBuilder<'a> {
    getter: Option<&'a dyn GetAuthInfo>,
}

impl<'a> TokenClientBuilder<'a> {
    pub fn set_getter(mut self, getter: Option<&'a dyn GetAuthInfo>) -> Self {
        self.getter = getter;
        self
    }
    pub fn build(self) -> TokenClient<'a> {
        if self.getter.is_none() {
            unimplemented!()
        }
        let client = TokenClient {
            getter: self.getter.unwrap(),
        };
        client
    }
}

impl<'a> TokenClient<'a> {
    #[allow(dead_code)]
    async fn run(
        &self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<(String, String, String)> {
        use aws_sdk_cognitoidentityprovider as provider;

        let config = aws_config::load_from_env().await;
        let cognito_client = provider::Client::new(&config);

        let (secret_key, client_id, user_pool_id): (String, String, String) =
            self.getter.run().await?;

        let srp_client = cognito_srp::SrpClient::new(
            &username,
            &password,
            &user_pool_id,
            &client_id,
            Some(&secret_key),
        );

        let initiate_auth_response = cognito_client
            .initiate_auth()
            .auth_flow(provider::types::AuthFlowType::UserSrpAuth)
            .client_id(client_id.clone())
            .set_auth_parameters(Some(srp_client.get_auth_params().unwrap()))
            .send()
            .await?;

        let challenge_params = initiate_auth_response
            .challenge_parameters
            .ok_or(anyhow::anyhow!("failed to get challenge parameters"))?;

        let challenge_responses = srp_client.process_challenge(challenge_params)?;

        let timestamp = challenge_responses.get("TIMESTAMP").unwrap();
        let signature = challenge_responses.get("PASSWORD_CLAIM_SIGNATURE").unwrap();
        let secret_block = challenge_responses
            .get("PASSWORD_CLAIM_SECRET_BLOCK")
            .unwrap();
        let secret_hash = challenge_responses.get("SECRET_HASH").unwrap();

        use aws_sdk_cognitoidentityprovider::types::ChallengeNameType;
        let respond = cognito_client
            .respond_to_auth_challenge()
            .client_id(client_id)
            .challenge_name(ChallengeNameType::PasswordVerifier)
            .challenge_responses("TIMESTAMP", timestamp)
            .challenge_responses("USERNAME", username)
            .challenge_responses("PASSWORD_CLAIM_SECRET_BLOCK", secret_block)
            .challenge_responses("PASSWORD_CLAIM_SIGNATURE", signature)
            .challenge_responses("SECRET_HASH", secret_hash)
            .send()
            .await?;

        let authentication_result = respond.authentication_result.unwrap();

        let id_token = authentication_result.id_token.unwrap();
        let access_token = authentication_result.access_token.unwrap();
        let refresh_token = authentication_result.refresh_token.unwrap();

        Ok((id_token, access_token, refresh_token))
    }
}
