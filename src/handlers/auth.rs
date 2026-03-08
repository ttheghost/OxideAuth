use crate::error::AppError;
use crate::jwt::generate_access_token;
use crate::models::user::{AuthResponse, LoginUserRequest};
use crate::models::{DbUser, RegisterUserRequest, UserResponse, UserRole};
use crate::state::AppState;
use crate::utils;
use crate::utils::{hash_password, verify_password};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header::SET_COOKIE};
use axum_extra::extract::CookieJar;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use sha2::{Digest, Sha256};

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), AppError> {
    if !utils::is_valid_email(&payload.email) {
        return Err(AppError::Validation(vec!["Email is not valid".to_string()]));
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

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginUserRequest>,
) -> Result<(HeaderMap, Json<AuthResponse>), AppError> {
    let user = sqlx::query_as!(
        DbUser,
        r#"
        SELECT
            id, username, email, password_hash,
            role AS "role: _", created_at, updated_at
        FROM users
        WHERE email = $1
        "#,
        payload.email
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::Unauthorized("Invalid email or password".to_string()))?;

    let is_valid = verify_password(payload.password, user.password_hash.clone())
        .await
        .map_err(|_| AppError::Internal(anyhow::anyhow!("Password verification failed")))?;

    if !is_valid {
        return Err(AppError::Unauthorized(
            "Invalid email or password".to_string(),
        ));
    }

    let role_str = match user.role {
        UserRole::Admin => "admin",
        UserRole::User => "user",
    };
    let (access_token, expires_in) = generate_access_token(user.id, role_str)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("Failed to generate token")))?;

    let mut refresh_token_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut refresh_token_bytes);
    let refresh_token = URL_SAFE_NO_PAD.encode(refresh_token_bytes);

    let refresh_hash = sha256::digest(refresh_token.clone());
    let expires_at = chrono::Utc::now() + chrono::Duration::days(7);

    sqlx::query!(
        r#"
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
        VALUES ($1, $2, $3)
        "#,
        user.id,
        refresh_hash,
        expires_at
    )
    .execute(&state.db)
    .await?;

    let response_body = AuthResponse {
        access_token,
        refresh_token: Some(refresh_token.clone()),
        token_type: "Bearer".to_string(),
        expires_in,
        user: UserResponse::from(user),
    };

    // TODO: Make the cookie attributes configurable via environment variables (e.g., COOKIE_SAMESITE=Strict vs None)
    let mut headers = HeaderMap::new();
    let cookie_str = format!(
        "refresh_token={}; HttpOnly; Secure; SameSite=Strict; Path=/login; Max-Age=604800",
        refresh_token
    );
    headers.insert(SET_COOKIE, cookie_str.parse().unwrap());

    Ok((headers, Json(response_body)))
}

pub async fn refresh(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(HeaderMap, Json<AuthResponse>), AppError> {
    let refresh_token = jar
        .get("refresh_token")
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| AppError::Unauthorized("No refresh token found".to_string()))?;

    let mut hasher = Sha256::new();
    hasher.update(refresh_token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());

    let mut tx = state.db.begin().await?;

    let record = sqlx::query!(
        r#"
        SELECT 
            rt.id as token_id, rt.user_id, rt.expires_at, rt.revoked,
            u.role AS "role: crate::models::user::UserRole"
        FROM refresh_tokens rt
        JOIN users u ON rt.user_id = u.id
        WHERE rt.token_hash = $1
        "#,
        token_hash
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::Unauthorized("Invalid refresh token".to_string()))?;

    if record.revoked {
        sqlx::query!(
            "DELETE FROM refresh_tokens WHERE user_id = $1",
            record.user_id
        )
        .execute(&mut *tx)
        .await?;
        return Err(AppError::Unauthorized("Token has been revoked".to_string()));
    }

    if record.expires_at < chrono::Utc::now() {
        return Err(AppError::Unauthorized("Refresh token expired".to_string()));
    }

    let role_str = match record.role {
        UserRole::Admin => "admin",
        UserRole::User => "user",
    };

    let (new_access_token, expires_in) = generate_access_token(record.user_id, role_str)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("Failed to generate token")))?;

    let mut new_rt_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut new_rt_bytes);
    let new_refresh_token = URL_SAFE_NO_PAD.encode(new_rt_bytes);

    let mut new_hasher = Sha256::new();
    new_hasher.update(new_refresh_token.as_bytes());
    let new_token_hash = format!("{:x}", new_hasher.finalize());
    let new_expires_at = chrono::Utc::now() + chrono::Duration::days(7);

    sqlx::query!("DELETE FROM refresh_tokens WHERE id = $1", record.token_id)
        .execute(&mut *tx)
        .await?;

    sqlx::query!(
        r#"
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
        VALUES ($1, $2, $3)
        "#,
        record.user_id,
        new_token_hash,
        new_expires_at
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let response_body = AuthResponse {
        access_token: new_access_token,
        refresh_token: None,
        token_type: "Bearer".to_string(),
        expires_in,
        user: UserResponse {
            id: record.user_id,
            username: "".to_string(),
            email: "".to_string(),
            role: record.role,
            created_at: chrono::Utc::now(),
        },
    };

    let mut headers = HeaderMap::new();
    let cookie_str = format!(
        "refresh_token={}; HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth; Max-Age=604800",
        new_refresh_token
    );
    headers.insert(SET_COOKIE, cookie_str.parse().unwrap());

    Ok((headers, Json(response_body)))
}

pub async fn logout(
    State(state): State<AppState>,
    claims: crate::jwt::Claims,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), AppError> {
    let now = chrono::Utc::now().timestamp() as usize;
    let ttl = claims.exp.saturating_sub(now);

    if ttl > 0 {
        let mut redis_conn =
            state.redis.get_multiplexed_async_connection().await.map_err(|e| {
                AppError::Internal(anyhow::anyhow!("Redis connection failed: {}", e))
            })?;

        let redis_key = format!("blocklist:{}", claims.jti);
        redis::cmd("SETEX")
            .arg(&redis_key)
            .arg(ttl)
            .arg("true")
            .query_async::<_>(&mut redis_conn)
            .await
            .map_err(|e| AppError::Redis(e))?
    }

    sqlx::query!("DELETE FROM refresh_tokens WHERE user_id = $1", claims.sub)
        .execute(&state.db)
        .await?;

    let clean_jar = jar.remove(axum_extra::extract::cookie::Cookie::from("refresh_token"));

    // Return 200 OK with the empty cookie jar
    Ok((clean_jar, StatusCode::OK))
}
