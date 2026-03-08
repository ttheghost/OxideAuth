mod state;
mod models;
mod handlers;
mod routes;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use dotenvy::dotenv;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::net::SocketAddr;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Init env vars and logging
    dotenv().ok();
    tracing_subscriber::fmt::init();

    // Read configuration
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let redis_url = env::var("REDIS_URL").expect("REDIS_URL must be set");
    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .expect("PORT must be a valid number");

    // Setup PostgreSQL connection pool
    info!("Connecting to PostgreSQL...");
    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    println!("Connected to PostgreSQL");

    info!("Connecting to Redis...");
    let redis_client = redis::Client::open(redis_url)?;

    let state = state::AppState {
        db: db_pool,
        redis: redis_client,
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/register", post(register))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    info!("Server listening on {}", addr);
    println!("Server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}

async fn register(
    State(state): State<state::AppState>,
    Json(payload): Json<models::user::RegisterUserRequest>,
) -> (StatusCode, Json<models::user::RegisterUserRequest>) {
    (StatusCode::CREATED, Json(payload))
}