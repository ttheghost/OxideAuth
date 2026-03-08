use jsonwebtoken::{encode, EncodingKey, Header};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{Utc, Duration};
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
}

pub fn generate_access_token(user_id: Uuid, role: &str) -> Result<(String, u64), jsonwebtoken::errors::Error> {
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "super_secret_development_key".into());

    let now = Utc::now();
    let expires_in_seconds = 15 * 60;
    let exp = (now + Duration::seconds(expires_in_seconds)).timestamp() as usize;
    let iat = now.timestamp() as usize;

    let claims = Claims {
        sub: user_id,
        role: role.to_string(),
        exp,
        iat,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;

    Ok((token, expires_in_seconds as u64))
}

pub fn verify_access_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "super_secret_development_key".into());

    let validation = Validation::new(jsonwebtoken::Algorithm::HS256);

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )?;

    Ok(token_data.claims)
}