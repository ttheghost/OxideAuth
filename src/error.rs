use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tracing::error;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Bad Request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not Found: {0}")]
    NotFound(String),

    #[error("Validation Error")]
    Validation(Vec<String>),

    #[error("Database Error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Redis Error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Internal Server Error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message, details) = match self {
            AppError::BadRequest(ref msg) => {
                (StatusCode::BAD_REQUEST, "BAD_REQUEST", msg.clone(), vec![])
            }
            AppError::Unauthorized(ref msg) => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                msg.clone(),
                vec![],
            ),
            AppError::Forbidden(ref msg) => {
                (StatusCode::FORBIDDEN, "FORBIDDEN", msg.clone(), vec![])
            }
            AppError::NotFound(ref msg) => {
                (StatusCode::NOT_FOUND, "NOT_FOUND", msg.clone(), vec![])
            }
            AppError::Validation(ref errs) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "VALIDATION_FAILED",
                "Input validation failed".to_string(),
                errs.clone(),
            ),
            AppError::Database(ref err) => {
                error!("Database error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_SERVER_ERROR",
                    "An internal server error occurred".to_string(),
                    vec![],
                )
            }
            AppError::Redis(ref err) => {
                error!("Redis error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_SERVER_ERROR",
                    "An internal server error occurred".to_string(),
                    vec![],
                )
            }
            AppError::Internal(ref err) => {
                error!("Internal system error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_SERVER_ERROR",
                    "An internal server error occurred".to_string(),
                    vec![],
                )
            }
        };

        let body = Json(json!({
            "error": {
                "code": code,
                "message": message,
                "details": details
            }
        }));

        (status, body).into_response()
    }
}
