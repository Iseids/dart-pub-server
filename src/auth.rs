use std::error::Error;

use axum::http::{HeaderMap, header};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};

use crate::{AppState, handlers::AppError};

pub(crate) fn hash_secret(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

pub(crate) fn new_secret() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("pub_{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) async fn require_token(
    state: &AppState,
    headers: &HeaderMap,
    publish: bool,
) -> Result<String, AppError> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
        .ok_or_else(|| AppError::unauthorized("A registry token is required. Run: dart pub token add <registry-url>"))?;

    let token_hash = hash_secret(bearer);
    let row = sqlx::query("SELECT role FROM access_tokens WHERE token_hash = ? AND revoked_at IS NULL")
        .bind(&token_hash)
        .fetch_optional(&state.db).await.map_err(AppError::database)?
        .ok_or_else(|| AppError::unauthorized("Invalid or revoked registry token"))?;
    let role: String = row.try_get("role").map_err(AppError::database)?;
    if publish && role != "publish" {
        return Err(AppError::forbidden("This token is read-only and cannot publish packages"));
    }
    // Best-effort: avoid a write-lock error interrupting package operations.
    let _ = sqlx::query("UPDATE access_tokens SET last_used_at = datetime('now') WHERE token_hash = ?")
        .bind(&token_hash).execute(&state.db).await;
    Ok(token_hash)
}

pub(crate) async fn check_read(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    if !state.cfg.public_reads {
        require_token(state, headers, false).await?;
    }
    Ok(())
}

pub(crate) async fn token_cli(pool: &SqlitePool, args: &[String]) -> Result<(), Box<dyn Error>> {
    match args {
        [cmd, name] if cmd == "create" => create_token(pool, name, "publish").await?,
        [cmd, name, role] if cmd == "create" && (role == "publish" || role == "read") => {
            create_token(pool, name, role).await?;
        }
        [cmd] if cmd == "list" => {
            let rows = sqlx::query("SELECT name, role, created_at, last_used_at, revoked_at FROM access_tokens ORDER BY name")
                .fetch_all(pool).await?;
            for row in rows {
                println!("{}\t{}\tcreated={}\tlast_used={}\t{}",
                    row.try_get::<String, _>("name")?,
                    row.try_get::<String, _>("role")?,
                    row.try_get::<String, _>("created_at")?,
                    row.try_get::<Option<String>, _>("last_used_at")?.unwrap_or_else(|| "never".into()),
                    if row.try_get::<Option<String>, _>("revoked_at")?.is_some() { "REVOKED" } else { "active" });
            }
        }
        [cmd, name] if cmd == "revoke" => {
            let result = sqlx::query("UPDATE access_tokens SET revoked_at = datetime('now') WHERE name = ? AND revoked_at IS NULL")
                .bind(name).execute(pool).await?;
            if result.rows_affected() == 0 { return Err(format!("No active token named '{name}'").into()); }
            println!("Revoked token: {name}");
        }
        _ => {
            return Err("Usage: pub-registry token create NAME [publish|read] | token list | token revoke NAME".into());
        }
    }
    Ok(())
}

async fn create_token(pool: &SqlitePool, name: &str, role: &str) -> Result<(), Box<dyn Error>> {
    if name.is_empty() || name.len() > 100 { return Err("Token name must contain 1–100 characters".into()); }
    let secret = new_secret();
    sqlx::query("INSERT INTO access_tokens (token_hash, name, role) VALUES (?, ?, ?)")
        .bind(hash_secret(&secret)).bind(name).bind(role).execute(pool).await?;
    println!("Token: {secret}");
    println!("Name: {name} | Role: {role}");
    println!("Store this token securely. It will NOT be shown again.");
    Ok(())
}
