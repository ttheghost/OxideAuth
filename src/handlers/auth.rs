use crate::error::AppError;
use crate::models::{DbUser, RegisterUserRequest, UserResponse, UserRole};
use crate::state::AppState;
use crate::utils;
use crate::utils::hash_password;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), AppError> {
    if !utils::is_valid_email(&payload.email) {
        return Err(AppError::Validation(vec!["Email is not valid".to_string()]));
    }

    let is_username_taken: bool = sqlx::query_scalar!(
        "SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)",
        payload.username
    )
    .fetch_one(&state.db)
    .await?
    .unwrap_or(false);

    if is_username_taken {
        return Err(AppError::BadRequest(
            "Username is already taken".to_string(),
        ));
    }

    let is_email_taken: bool = sqlx::query_scalar!(
        "SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)",
        payload.email
    )
    .fetch_one(&state.db)
    .await?
    .unwrap_or(false);

    if is_email_taken {
        return Err(AppError::BadRequest("Email is already taken".to_string()));
    }

    let password_hash = hash_password(payload.password).await.map_err(|e| {
        tracing::error!("Password hashing failed: {:?}", e);
        AppError::Internal(anyhow::anyhow!("Internal server error"))
    })?;

    let insert_result = sqlx::query_as!(
        DbUser,
        r#"
        INSERT INTO users (username, email, password_hash)
        VALUES ($1, $2, $3)
        RETURNING id, username, email, password_hash, role AS "role: _", created_at, updated_at
        "#,
        payload.username,
        payload.email,
        password_hash
    )
    .fetch_one(&state.db)
    .await;

    let db_user = match insert_result {
        Ok(user) => user,
        Err(e) => {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.is_unique_violation() {
                    return Err(AppError::BadRequest(
                        "User with this email or username already exists".to_string(),
                    ));
                }
            }
            return Err(AppError::Database(e));
        }
    };

    let response = UserResponse::from(db_user);

    Ok((StatusCode::CREATED, Json(response)))
}
