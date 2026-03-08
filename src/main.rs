use axum::{routing::get, Router};
use dotenvy::dotenv;
use std::env;
use std::net::SocketAddr;
use sqlx::postgres::PgPoolOptions;
use tracing::info;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub redis: redis::Client,
}

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

    let state = AppState {
        db: db_pool,
        redis: redis_client,
    };

    let app = Router::new()
        .route("/health", get(health_check))
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