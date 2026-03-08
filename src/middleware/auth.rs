use crate::{
    error::AppError,
    jwt::{Claims, verify_access_token},
};
use axum::{extract::FromRequestParts, http::request::Parts};

impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?;

        if !auth_header.starts_with("Bearer ") {
            return Err(AppError::Unauthorized(
                "Invalid Authorization header format".to_string(),
            ));
        }

        let token = auth_header.trim_start_matches("Bearer ");

        let claims = verify_access_token(token).map_err(|e| {
            tracing::warn!("JWT validation failed: {:?}", e);
            AppError::Unauthorized("Invalid or expired token".to_string())
        })?;

        Ok(claims)
    }
}
