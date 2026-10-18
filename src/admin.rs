use std::{error::Error, io::Write, path::Path};

use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};

use crate::{AppState, auth};

const SESSION_COOKIE: &str = "admin_session";
const SESSION_HOURS: u32 = 12;

pub(crate) struct AdminError {
    status: StatusCode,
    message: String,
}

impl AdminError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "Sign in to continue")
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn database(error: impl std::fmt::Display) -> Self {
        tracing::error!(error = %error, "admin database operation failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "An internal error occurred",
        )
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(json!({"error": self.message}))).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

#[derive(Clone)]
struct AdminSession {
    username: String,
    must_change_password: bool,
}

#[derive(Deserialize)]
pub(crate) struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
pub(crate) struct CreateTokenForm {
    name: String,
    role: String,
}

#[derive(Deserialize)]
pub(crate) struct RevokeTokenForm {
    name: String,
}

#[derive(Deserialize)]
pub(crate) struct ChangePasswordForm {
    current_password: String,
    new_password: String,
}

pub(crate) async fn initialize(
    pool: &SqlitePool,
    username: String,
    initial_password: Option<String>,
    data_dir: &Path,
) -> Result<(), Box<dyn Error>> {
    let exists = sqlx::query_scalar::<_, i64>("SELECT 1 FROM admin_users WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    if exists.is_some() {
        sqlx::query("DELETE FROM admin_sessions WHERE expires_at <= datetime('now')")
            .execute(pool)
            .await?;
        return Ok(());
    }

    let username = username.trim().to_owned();
    if username.is_empty() || username.len() > 64 {
        return Err("ADMIN_USERNAME must contain 1–64 characters".into());
    }
    let password_was_supplied = initial_password
        .as_ref()
        .is_some_and(|value| !value.is_empty());
    let password = initial_password
        .filter(|value| !value.is_empty())
        .unwrap_or_else(auth::new_secret);
    if password.len() < 12 {
        return Err("ADMIN_INITIAL_PASSWORD must be at least 12 characters".into());
    }

    let password_for_hash = password.clone();
    let hash = tokio::task::spawn_blocking(move || password_hash(&password_for_hash))
        .await?
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    if !password_was_supplied {
        write_initial_password(&data_dir.join("admin-initial-password"), &password)?;
    }
    sqlx::query("INSERT INTO admin_users (id, username, password_hash, must_change_password) VALUES (1, ?, ?, 1)")
        .bind(&username)
        .bind(hash)
        .execute(pool)
        .await?;

    if !password_was_supplied {
        tracing::warn!(
            "Generated initial admin password; retrieve it from /data/admin-initial-password and change it after signing in"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn write_initial_password(path: &Path, password: &str) -> Result<(), std::io::Error> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(password.as_bytes())?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn write_initial_password(path: &Path, password: &str) -> Result<(), std::io::Error> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(password.as_bytes())
}

fn password_hash(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

fn password_matches(
    password: &str,
    encoded_hash: &str,
) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(encoded_hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

async fn hash_password(password: String) -> Result<String, AdminError> {
    tokio::task::spawn_blocking(move || password_hash(&password))
        .await
        .map_err(AdminError::database)?
        .map_err(AdminError::database)
}

async fn verify_password(password: String, encoded_hash: String) -> Result<bool, AdminError> {
    tokio::task::spawn_blocking(move || password_matches(&password, &encoded_hash))
        .await
        .map_err(AdminError::database)?
        .map_err(AdminError::database)
}

fn cookie_secret(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(name, value)| (name == SESSION_COOKIE).then_some(value))
        .filter(|value| !value.is_empty())
}

fn session_cookie(secret: Option<&str>, secure: bool) -> Result<HeaderValue, AdminError> {
    let cookie = match secret {
        Some(secret) => format!(
            "{SESSION_COOKIE}={secret}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age={}",
            SESSION_HOURS * 60 * 60
        ),
        None => format!("{SESSION_COOKIE}=; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=0"),
    };
    let cookie = if secure {
        format!("{cookie}; Secure")
    } else {
        cookie
    };
    HeaderValue::from_str(&cookie).map_err(AdminError::database)
}

fn json_response(value: Value) -> Response {
    let mut response = Json(value).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn require_session(
    state: &AppState,
    headers: &HeaderMap,
    allow_password_change: bool,
) -> Result<AdminSession, AdminError> {
    let secret = cookie_secret(headers).ok_or_else(AdminError::unauthorized)?;
    let row = sqlx::query(
        "SELECT u.username, u.must_change_password \
         FROM admin_sessions s CROSS JOIN admin_users u \
         WHERE s.session_hash = ? AND s.expires_at > datetime('now') AND u.id = 1",
    )
    .bind(auth::hash_secret(secret))
    .fetch_optional(&state.db)
    .await
    .map_err(AdminError::database)?
    .ok_or_else(AdminError::unauthorized)?;
    let session = AdminSession {
        username: row.try_get("username").map_err(AdminError::database)?,
        must_change_password: row
            .try_get::<i64, _>("must_change_password")
            .map_err(AdminError::database)?
            != 0,
    };
    if session.must_change_password && !allow_password_change {
        return Err(AdminError::forbidden(
            "Change the initial password before using the admin dashboard",
        ));
    }
    Ok(session)
}

pub(crate) async fn page() -> Html<&'static str> {
    Html(include_str!("admin.html"))
}

pub(crate) async fn login(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Result<Response, AdminError> {
    let row = sqlx::query(
        "SELECT username, password_hash, must_change_password FROM admin_users WHERE username = ?",
    )
    .bind(form.username.trim())
    .fetch_optional(&state.db)
    .await
    .map_err(AdminError::database)?
    .ok_or_else(AdminError::unauthorized)?;
    let encoded_hash: String = row.try_get("password_hash").map_err(AdminError::database)?;
    if !verify_password(form.password, encoded_hash).await? {
        return Err(AdminError::unauthorized());
    }

    let secret = auth::new_secret();
    let hash = auth::hash_secret(&secret);
    sqlx::query("INSERT INTO admin_sessions (session_hash, expires_at) VALUES (?, datetime('now', '+12 hours'))")
        .bind(hash)
        .execute(&state.db)
        .await
        .map_err(AdminError::database)?;

    let username: String = row.try_get("username").map_err(AdminError::database)?;
    let must_change_password: i64 = row
        .try_get("must_change_password")
        .map_err(AdminError::database)?;
    let mut response = json_response(json!({
        "username": username,
        "must_change_password": must_change_password != 0,
    }));
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(Some(&secret), state.cfg.secure_admin_cookie)?,
    );
    Ok(response)
}

pub(crate) async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(secret) = cookie_secret(&headers) {
        let _ = sqlx::query("DELETE FROM admin_sessions WHERE session_hash = ?")
            .bind(auth::hash_secret(secret))
            .execute(&state.db)
            .await;
    }
    let mut response = json_response(json!({"success": true}));
    if let Ok(cookie) = session_cookie(None, state.cfg.secure_admin_cookie) {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    response
}

pub(crate) async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    let session = require_session(&state, &headers, true).await?;
    Ok(json_response(json!({
        "username": session.username,
        "must_change_password": session.must_change_password,
    })))
}

pub(crate) async fn packages(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    require_session(&state, &headers, false).await?;
    let rows = sqlx::query(
        "SELECT name, version, archive_size, created_at, archive_sha256 \
         FROM package_versions ORDER BY created_at DESC, name, version DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(AdminError::database)?;
    let mut packages = Vec::with_capacity(rows.len());
    for row in rows {
        packages.push(json!({
            "name": row.try_get::<String, _>("name").map_err(AdminError::database)?,
            "version": row.try_get::<String, _>("version").map_err(AdminError::database)?,
            "archive_size": row.try_get::<i64, _>("archive_size").map_err(AdminError::database)?,
            "created_at": row.try_get::<String, _>("created_at").map_err(AdminError::database)?,
            "archive_sha256": row.try_get::<String, _>("archive_sha256").map_err(AdminError::database)?,
        }));
    }
    Ok(json_response(json!({"packages": packages})))
}

pub(crate) async fn tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AdminError> {
    require_session(&state, &headers, false).await?;
    let rows = sqlx::query(
        "SELECT name, role, created_at, last_used_at, revoked_at \
         FROM access_tokens ORDER BY created_at DESC, name",
    )
    .fetch_all(&state.db)
    .await
    .map_err(AdminError::database)?;
    let mut tokens = Vec::with_capacity(rows.len());
    for row in rows {
        tokens.push(json!({
            "name": row.try_get::<String, _>("name").map_err(AdminError::database)?,
            "role": row.try_get::<String, _>("role").map_err(AdminError::database)?,
            "created_at": row.try_get::<String, _>("created_at").map_err(AdminError::database)?,
            "last_used_at": row.try_get::<Option<String>, _>("last_used_at").map_err(AdminError::database)?,
            "revoked_at": row.try_get::<Option<String>, _>("revoked_at").map_err(AdminError::database)?,
        }));
    }
    Ok(json_response(json!({"tokens": tokens})))
}

pub(crate) async fn create_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateTokenForm>,
) -> Result<Response, AdminError> {
    require_session(&state, &headers, false).await?;
    let name = form.name.trim();
    if name.is_empty() || name.len() > 100 || name.chars().any(char::is_control) {
        return Err(AdminError::bad(
            "Token name must contain 1–100 printable characters",
        ));
    }
    if form.role != "publish" && form.role != "read" {
        return Err(AdminError::bad("Token role must be read or publish"));
    }

    let secret = auth::new_secret();
    let result = sqlx::query("INSERT INTO access_tokens (token_hash, name, role) VALUES (?, ?, ?)")
        .bind(auth::hash_secret(&secret))
        .bind(name)
        .bind(&form.role)
        .execute(&state.db)
        .await;
    if let Err(error) = result {
        if error
            .as_database_error()
            .is_some_and(|database_error| database_error.is_unique_violation())
        {
            return Err(AdminError::new(
                StatusCode::CONFLICT,
                "A token with that name already exists",
            ));
        }
        return Err(AdminError::database(error));
    }
    Ok(json_response(
        json!({"token": secret, "name": name, "role": form.role}),
    ))
}

pub(crate) async fn revoke_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RevokeTokenForm>,
) -> Result<Response, AdminError> {
    require_session(&state, &headers, false).await?;
    let result = sqlx::query("UPDATE access_tokens SET revoked_at = datetime('now') WHERE name = ? AND revoked_at IS NULL")
        .bind(form.name.trim())
        .execute(&state.db)
        .await
        .map_err(AdminError::database)?;
    if result.rows_affected() == 0 {
        return Err(AdminError::new(
            StatusCode::NOT_FOUND,
            "No active token with that name",
        ));
    }
    Ok(json_response(json!({"success": true})))
}

pub(crate) async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ChangePasswordForm>,
) -> Result<Response, AdminError> {
    let session = require_session(&state, &headers, true).await?;
    if form.new_password.len() < 12 {
        return Err(AdminError::bad(
            "New password must be at least 12 characters",
        ));
    }
    if form.current_password == form.new_password {
        return Err(AdminError::bad(
            "Choose a password you have not used for this account",
        ));
    }

    let encoded_hash: String =
        sqlx::query_scalar("SELECT password_hash FROM admin_users WHERE id = 1")
            .fetch_one(&state.db)
            .await
            .map_err(AdminError::database)?;
    if !verify_password(form.current_password, encoded_hash).await? {
        return Err(AdminError::bad("Current password is incorrect"));
    }
    let new_hash = hash_password(form.new_password).await?;
    let new_secret = auth::new_secret();
    let new_session_hash = auth::hash_secret(&new_secret);
    let mut transaction = state.db.begin().await.map_err(AdminError::database)?;
    sqlx::query("UPDATE admin_users SET password_hash = ?, must_change_password = 0, updated_at = datetime('now') WHERE id = 1")
        .bind(new_hash)
        .execute(&mut *transaction)
        .await
        .map_err(AdminError::database)?;
    sqlx::query("INSERT INTO admin_sessions (session_hash, expires_at) VALUES (?, datetime('now', '+12 hours'))")
        .bind(&new_session_hash)
        .execute(&mut *transaction)
        .await
        .map_err(AdminError::database)?;
    sqlx::query("DELETE FROM admin_sessions WHERE session_hash != ?")
        .bind(&new_session_hash)
        .execute(&mut *transaction)
        .await
        .map_err(AdminError::database)?;
    transaction.commit().await.map_err(AdminError::database)?;
    if let Err(error) =
        tokio::fs::remove_file(state.cfg.data_dir.join("admin-initial-password")).await
    {
        if error.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(error = %error, "could not remove the one-time admin password file");
        }
    }

    let mut response = json_response(json!({"success": true, "username": session.username}));
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie(Some(&new_secret), state.cfg.secure_admin_cookie)?,
    );
    Ok(response)
}
