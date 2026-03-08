use crate::{
    error::AppError,
    jwt::{Claims, verify_access_token},
};
use axum::{extract::FromRequestParts, http::request::Parts};
use crate::state::AppState;

impl FromRequestParts<AppState> for Claims
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
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

        // Checking Redis Blocklist
        let mut redis_conn = state.redis.get_multiplexed_async_connection().await
            .map_err(|_| AppError::Internal(anyhow::anyhow!("Redis error")))?;

        let redis_key = format!("blocklist:{}", claims.jti);
        let is_blocked: bool = redis::cmd("EXISTS")
            .arg(&redis_key)
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(false);

        if is_blocked {
            return Err(AppError::Unauthorized("Session has been terminated".to_string()));
        }

        Ok(claims)
    }
}
