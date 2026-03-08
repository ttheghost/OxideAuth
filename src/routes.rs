use axum::routing::{get, post};
use axum::Router;
use crate::handlers::auth;
use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/register", post(auth::register))
        .with_state(state)
}
