mod archive;
mod admin;
mod auth;
mod handlers;

use std::{env, net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc, time::Duration};

use axum::{Router, extract::DefaultBodyLimit, routing::{get, post}};
use sqlx::{SqlitePool, sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions}};
use tokio::fs;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub(crate) struct AppState {
    pub db: SqlitePool,
    pub cfg: Arc<Config>,
}

pub(crate) struct Config {
    pub base_url: String,
    pub data_dir: PathBuf,
    pub public_reads: bool,
    pub max_upload_bytes: usize,
    pub max_unpacked_bytes: u64,
    pub secure_admin_cookie: bool,
}

fn env_bool(name: &str, default: bool) -> bool {
    env::var(name)
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(default)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "pub_registry=info,dart_pub_registry=info".into()))
        .init();

    let data_dir = PathBuf::from(env::var("DATA_DIR").unwrap_or_else(|_| "./data".into()));
    fs::create_dir_all(data_dir.join("staging")).await?;
    fs::create_dir_all(data_dir.join("packages")).await?;

    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://./data/registry.db".into());
    let db_options = SqliteConnectOptions::from_str(&database_url)?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(10));
    let pool = SqlitePoolOptions::new().max_connections(5).connect_with(db_options).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;

    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "token") {
        return auth::token_cli(&pool, &args[1..]).await;
    }
    if !args.is_empty() && args[0] != "serve" {
        return Err(format!("Unknown command: {}. Usage: pub-registry [serve | token create NAME [read|publish] | token list | token revoke NAME]", args[0]).into());
    }

    let base_url = env::var("PUBLIC_BASE_URL")
        .unwrap_or_else(|_| "http://localhost:6844".into())
        .trim_end_matches('/')
        .to_string();
    if !(base_url.starts_with("https://") || base_url.starts_with("http://"))
        || base_url.contains('?') || base_url.contains('#') || base_url.contains('@') {
        return Err("PUBLIC_BASE_URL must be an http(s) URL without userinfo, query, or fragment".into());
    }
    let max_upload_bytes = env::var("MAX_UPLOAD_MB")
        .unwrap_or_else(|_| "32".into()).parse::<usize>()? * 1024 * 1024;
    let cfg = Arc::new(Config {
        secure_admin_cookie: base_url.starts_with("https://"),
        base_url,
        data_dir,
        public_reads: env_bool("PUBLIC_READS", true),
        max_upload_bytes,
        max_unpacked_bytes: 256 * 1024 * 1024,
    });
    admin::initialize(
        &pool,
        env::var("ADMIN_USERNAME").unwrap_or_else(|_| "admin".into()),
        env::var("ADMIN_INITIAL_PASSWORD").ok(),
        &cfg.data_dir,
    ).await?;
    let state = AppState { db: pool, cfg };

    // Expire interrupted uploads and remove orphaned temporary files every hour.
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(3600));
        loop {
            ticker.tick().await;
            if let Err(err) = cleanup_expired_uploads(&cleanup_state).await {
                tracing::warn!(error = %err, "upload cleanup failed");
            }
        }
    });

    let app = Router::new()
        .route("/", get(handlers::home))
        .route("/admin", get(admin::page))
        .route("/admin/login", get(admin::page))
        .route("/admin/api/login", post(admin::login))
        .route("/admin/api/logout", post(admin::logout))
        .route("/admin/api/me", get(admin::me))
        .route("/admin/api/packages", get(admin::packages))
        .route("/admin/api/tokens", get(admin::tokens).post(admin::create_token))
        .route("/admin/api/tokens/revoke", post(admin::revoke_token))
        .route("/admin/api/password", post(admin::change_password))
        .route("/healthz", get(handlers::health))
        .route("/api/search", get(handlers::search))
        .route("/api/packages/versions/new", get(handlers::begin_publish))
        .route("/api/packages/{name}", get(handlers::list_versions))
        .route("/api/packages/{name}/versions/{version}", get(handlers::version_info))
        .route("/packages/{name}/versions/{archive}", get(handlers::download))
        .route("/api/uploads/{id}", post(handlers::upload))
        .route("/api/uploads/{id}/finalize", get(handlers::finalize))
        .layer(DefaultBodyLimit::max(state.cfg.max_upload_bytes.saturating_add(2 * 1024 * 1024)))
        .with_state(state);

    let address: SocketAddr = env::var("BIND_ADDRESS")
        .unwrap_or_else(|_| "0.0.0.0:6844".into()).parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "Dart Pub registry listening");
    axum::serve(listener, app).with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    }).await?;
    Ok(())
}

async fn cleanup_expired_uploads(state: &AppState) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use sqlx::Row;
    let rows = sqlx::query("SELECT stage_filename FROM upload_sessions WHERE expires_at <= datetime('now')")
        .fetch_all(&state.db).await?;
    for row in rows {
        if let Some(filename) = row.try_get::<Option<String>, _>("stage_filename")? {
            // File names are generated internally, not received from HTTP clients.
            let _ = fs::remove_file(state.cfg.data_dir.join("staging").join(filename)).await;
        }
    }
    sqlx::query("DELETE FROM upload_sessions WHERE expires_at <= datetime('now')")
        .execute(&state.db).await?;

    // Also sweep abandoned .part files from interrupted multipart requests.
    let mut entries = fs::read_dir(state.cfg.data_dir.join("staging")).await?;
    while let Some(entry) = entries.next_entry().await? {
        if !entry.file_name().to_string_lossy().ends_with(".part") { continue; }
        let metadata = entry.metadata().await?;
        if metadata.modified()?.elapsed().unwrap_or_default() > Duration::from_secs(3600) {
            let _ = fs::remove_file(entry.path()).await;
        }
    }
    Ok(())
}
