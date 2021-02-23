use url::form_urlencoded::Serializer;

use http::Request;
use serde::{Deserialize, Serialize};
use tame_oauth::{Error, Token};

/// This is the schema of the server's response.
#[derive(serde::Deserialize, Debug)]
struct TokenResponse {
    /// The actual token
    access_token: String,

    /// A refresh token which may or may not have been returned by the provider
    refresh_token: Option<String>,

    /// The id token - could potentially be None from some providers?
    id_token: String,

    /// The token type - most often `bearer`
    token_type: String,
    /// The time until the token expires and a new one needs to be requested
    expires_in: i64,
    /// The scope used for this token - most often `openid`
    scope: String,
}

impl Into<Token> for TokenResponse {
    fn into(self) -> Token {
        let expires_ts = chrono::Utc::now().timestamp() + self.expires_in;

        let refresh_token = if self.refresh_token.is_some() {
            self.refresh_token.unwrap()
        } else {
            "".to_string()
        };

        Token {
            access_token: self.access_token,
            token_type: self.token_type,
            refresh_token,
            expires_in: Some(self.expires_in),
            expires_in_timestamp: Some(expires_ts),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct EmbarkTokenExchangeRequest {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    grant_type: String,
    code: String,
}

/// Server response schema
#[derive(Serialize, Deserialize, Debug)]
struct EmbarkTokenResponse {
    id_token: String,
    access_token: String,
    refresh_token: String,
    token_type: String,
    scope: String,
    expires_in: i64,
}

pub fn exchange_token_request(
    uri: String,
    redirect_uri: String,
    client_id: String,
    client_secret: String,
    auth_code: String,
) -> Request<Vec<u8>> {
    let body = Serializer::new(String::new())
        .append_pair("client_id", &client_id)
        .append_pair("client_secret", &client_secret)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &auth_code)
        .finish();

    let req_body = Vec::from(body);
    // let body_str = serde_json::to_string(&auth_body).unwrap();
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(req_body)
        .unwrap()
}

/// Once a response has been received for a token request, call this
/// method to deserialize the token and store it in the cache so that
/// future API requests don't have to retrieve a new token, until it
/// expires.
/// NOTE: Copied directly from `tame-oauth` - could be made standalone from `ServiceAccountAccess`
pub fn parse_token_response<S>(response: http::Response<S>) -> Result<Token, Error>
where
    S: AsRef<[u8]>,
{
    let (parts, body) = response.into_parts();

    if !parts.status.is_success() {
        return Err(Error::HttpStatus(parts.status));
    }

    let token_res: TokenResponse = serde_json::from_slice(body.as_ref())?;
    let token: Token = token_res.into();

    Ok(token)
}
