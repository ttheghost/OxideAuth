use crate::{
    error::AppError,
    jwt::Claims,
    models::user::{DbUser, UserResponse},
    state::AppState,
};
use axum::{Json, extract::State};

pub async fn get_me(
    State(state): State<AppState>,
    claims: Claims,
) -> Result<Json<UserResponse>, AppError> {
    let user = sqlx::query_as!(
        DbUser,
        r#"
        SELECT id, username, email, password_hash, role AS "role: _", created_at, updated_at
        FROM users
        WHERE id = $1
        "#,
        claims.sub
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(UserResponse::from(user)))
}
