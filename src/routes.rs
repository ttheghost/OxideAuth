use crate::handlers::{auth, users};
use crate::state::AppState;
use axum::Router;
use axum::routing::{get, post};

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/register", post(auth::register))
        .route("/login", post(auth::login))
        .route("/refresh", post(auth::refresh))
        .route("/me", get(users::get_me))
        .with_state(state)
}
