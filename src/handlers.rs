use std::path::PathBuf;

use axum::{
    Json,
    body::Body,
    extract::{Multipart, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use semver::Version;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use tokio::{fs, io::AsyncWriteExt};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::{AppState, archive::{self, ArchiveInfo}, auth};

const PUB_JSON: &str = "application/vnd.pub.v2+json";

pub(crate) struct AppError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl AppError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into() }
    }
    pub fn bad(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }
    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "Package, version, or upload not found")
    }
    fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }
    pub fn database(err: impl std::fmt::Display) -> Self {
        tracing::error!(error = %err, "database error");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "An internal database error occurred")
    }
    fn io(err: impl std::fmt::Display) -> Self {
        tracing::error!(error = %err, "file operation failed");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "An internal file error occurred")
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(json!({"error": {"code": self.code, "message": self.message}}))).into_response();
        response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(PUB_JSON));
        if self.status == StatusCode::UNAUTHORIZED || self.status == StatusCode::FORBIDDEN {
            response.headers_mut().insert(header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"pub\""));
        }
        response
    }
}

fn pub_json(value: Value) -> Response {
    let mut response = Json(value).into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(PUB_JSON));
    response
}

fn verify_package_name(name: &str) -> Result<(), AppError> {
    if archive::valid_name(name) { Ok(()) } else { Err(AppError::bad("Invalid package name")) }
}
fn verify_version(version: &str) -> Result<(), AppError> {
    if archive::valid_version(version) { Ok(()) } else { Err(AppError::bad("Invalid package version")) }
}
fn archive_path(state: &AppState, name: &str, version: &str) -> PathBuf {
    state.cfg.data_dir.join("packages").join(name).join(format!("{version}.tar.gz"))
}

pub(crate) async fn health(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    sqlx::query("SELECT 1").execute(&state.db).await.map_err(AppError::database)?;
    Ok(Json(json!({"status": "ok"})))
}

fn escape_html(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;")
        .replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

pub(crate) async fn home(State(state): State<AppState>, headers: HeaderMap) -> Result<Html<String>, AppError> {
    let content = if auth::check_read(&state, &headers).await.is_ok() {
        let rows = sqlx::query("SELECT name, COUNT(*) AS versions FROM package_versions GROUP BY name ORDER BY name")
            .fetch_all(&state.db).await.map_err(AppError::database)?;
        if rows.is_empty() { "<p>No packages yet. Publish your first package using <code>dart pub publish</code>.</p>".to_owned() }
        else {
            let mut result = String::from("<div class='packages'>");
            for row in rows {
                let name: String = row.try_get("name").map_err(AppError::database)?;
                let count: i64 = row.try_get("versions").map_err(AppError::database)?;
                result.push_str(&format!("<div class='package'><strong>{}</strong><span>{count} version(s)</span></div>", escape_html(&name)));
            }
            result.push_str("</div>"); result
        }
    } else {
        "<p>This registry has private reads enabled. Use <code>dart pub token add</code> and the Pub API to access packages.</p>".to_owned()
    };
    let url = escape_html(&state.cfg.base_url);
    let body = format!(r##"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Dart Pub Registry</title><style>
    :root{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;color-scheme:light}}
    body{{background:#f5f7fb;color:#162438;margin:0}}
    main{{max-width:850px;margin:70px auto;padding:0 22px}}
    h1{{font-size:2.6rem;letter-spacing:-.045em;margin-bottom:10px}}
    .muted{{color:#64748b}}.mark{{background:#0ea5e9;color:white;border-radius:12px;padding:7px 13px;font-weight:700}}
    .panel{{background:white;border:1px solid #e2e8f0;padding:26px;border-radius:16px;margin-top:25px;box-shadow:0 6px 25px #0f172a09}}
    code,pre{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}
    pre{{background:#0f172a;color:#bae6fd;padding:18px;border-radius:10px;overflow:auto}}
    .packages{{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}}
    .package{{padding:15px;border:1px solid #e2e8f0;border-radius:10px;display:flex;justify-content:space-between;gap:8px}}
    .package span{{color:#64748b;font-size:.85em}}a{{color:#0284c7}}
    </style></head><body><main><span class="mark">PUB</span><h1>Private package registry</h1>
    <p class="muted">A lightweight Dart &amp; Flutter package server powered by Rust, Tokio, Axum and SQLite.</p>
    <div class="panel"><h2>Packages</h2>{content}</div>
    <div class="panel"><h2>Use this repository</h2><p>Add a hosted dependency to your <code>pubspec.yaml</code>:</p>
    <pre>dependencies:
  my_package:
    hosted: {url}
    version: ^1.0.0</pre>
    <p>Publish by setting <code>publish_to: {url}</code> in your package pubspec and running <code>dart pub publish</code>. Publishing requires an administrator-created token and HTTPS.</p>
    <p><a href="{url}/admin">Registry administration</a> · <a href="{url}/healthz">Health status</a></p></div></main></body></html>"##);
    Ok(Html(body))
}

#[derive(Deserialize)]
pub(crate) struct SearchParams { q: Option<String> }

pub(crate) async fn search(
    State(state): State<AppState>, headers: HeaderMap, Query(params): Query<SearchParams>,
) -> Result<Response, AppError> {
    auth::check_read(&state, &headers).await?;
    let term = params.q.unwrap_or_default();
    let like = format!("%{}%", term.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
    let rows = sqlx::query("SELECT name, COUNT(*) AS versions FROM package_versions WHERE name LIKE ? ESCAPE '\\' GROUP BY name ORDER BY name LIMIT 100")
        .bind(like).fetch_all(&state.db).await.map_err(AppError::database)?;
    let mut packages = Vec::new();
    for row in rows {
        packages.push(json!({"name": row.try_get::<String,_>("name").map_err(AppError::database)?,
            "versions": row.try_get::<i64,_>("versions").map_err(AppError::database)?}));
    }
    Ok(pub_json(json!({"packages": packages})))
}

fn version_json(state: &AppState, row: &sqlx::sqlite::SqliteRow, name: &str) -> Result<Value, AppError> {
    let version: String = row.try_get("version").map_err(AppError::database)?;
    let spec: String = row.try_get("pubspec_json").map_err(AppError::database)?;
    let sha: String = row.try_get("archive_sha256").map_err(AppError::database)?;
    let pubspec: Value = serde_json::from_str(&spec).map_err(AppError::database)?;
    Ok(json!({"version": version, "pubspec": pubspec,
        "archive_url": format!("{}/packages/{}/versions/{}.tar.gz", state.cfg.base_url, name, version),
        "archive_sha256": sha}))
}

pub(crate) async fn list_versions(
    State(state): State<AppState>, Path(name): Path<String>, headers: HeaderMap,
) -> Result<Response, AppError> {
    auth::check_read(&state, &headers).await?;
    verify_package_name(&name)?;
    let rows = sqlx::query("SELECT version, pubspec_json, archive_sha256 FROM package_versions WHERE name = ?")
        .bind(&name).fetch_all(&state.db).await.map_err(AppError::database)?;
    if rows.is_empty() { return Err(AppError::not_found()); }
    let mut versions = Vec::new();
    for row in &rows { versions.push(version_json(&state, row, &name)?); }
    versions.sort_by(|a, b| {
        let av = Version::parse(a["version"].as_str().unwrap_or("0.0.0")).unwrap();
        let bv = Version::parse(b["version"].as_str().unwrap_or("0.0.0")).unwrap();
        av.cmp(&bv)
    });
    let latest = versions.last().cloned();
    Ok(pub_json(json!({"name": name, "latest": latest, "versions": versions})))
}

pub(crate) async fn version_info(
    State(state): State<AppState>, Path((name, version)): Path<(String, String)>, headers: HeaderMap,
) -> Result<Response, AppError> {
    auth::check_read(&state, &headers).await?;
    verify_package_name(&name)?;
    verify_version(&version)?;
    let row = sqlx::query("SELECT version, pubspec_json, archive_sha256 FROM package_versions WHERE name = ? AND version = ?")
        .bind(&name).bind(&version).fetch_optional(&state.db).await.map_err(AppError::database)?
        .ok_or_else(AppError::not_found)?;
    Ok(pub_json(version_json(&state, &row, &name)?))
}

pub(crate) async fn download(
    State(state): State<AppState>, Path((name, archive)): Path<(String, String)>, headers: HeaderMap,
) -> Result<Response, AppError> {
    auth::check_read(&state, &headers).await?;
    verify_package_name(&name)?;
    let version = archive.strip_suffix(".tar.gz").ok_or_else(AppError::not_found)?;
    verify_version(version)?;
    let exists = sqlx::query("SELECT 1 FROM package_versions WHERE name = ? AND version = ?")
        .bind(&name).bind(version).fetch_optional(&state.db).await.map_err(AppError::database)?;
    if exists.is_none() { return Err(AppError::not_found()); }
    let file = fs::File::open(archive_path(&state, &name, version)).await.map_err(AppError::io)?;
    let size = file.metadata().await.map_err(AppError::io)?.len();
    let mut response = Body::from_stream(ReaderStream::new(file)).into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    response.headers_mut().insert(header::CONTENT_LENGTH,
        HeaderValue::from_str(&size.to_string()).map_err(AppError::io)?);
    response.headers_mut().insert(header::CACHE_CONTROL,
        HeaderValue::from_static(if state.cfg.public_reads { "public, max-age=31536000, immutable" } else { "private, no-store" }));
    Ok(response)
}

pub(crate) async fn begin_publish(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, AppError> {
    let publisher_hash = auth::require_token(&state, &headers, true).await?;
    let id = Uuid::new_v4().to_string();
    let secret = auth::new_secret();
    sqlx::query("INSERT INTO upload_sessions (id, secret_hash, publisher_hash, status, expires_at) VALUES (?, ?, ?, 'initiated', datetime('now', '+30 minutes'))")
        .bind(&id).bind(auth::hash_secret(&secret)).bind(publisher_hash)
        .execute(&state.db).await.map_err(AppError::database)?;
    Ok(pub_json(json!({
        "url": format!("{}/api/uploads/{}", state.cfg.base_url, id),
        "fields": {"upload_token": secret}
    })))
}

pub(crate) async fn upload(
    State(state): State<AppState>, Path(id): Path<String>, mut multipart: Multipart,
) -> Result<Response, AppError> {
    if Uuid::parse_str(&id).is_err() { return Err(AppError::not_found()); }
    let row = sqlx::query("SELECT secret_hash, status FROM upload_sessions WHERE id = ? AND expires_at > datetime('now')")
        .bind(&id).fetch_optional(&state.db).await.map_err(AppError::database)?
        .ok_or_else(AppError::not_found)?;
    let current_status: String = row.try_get("status").map_err(AppError::database)?;
    if current_status != "initiated" { return Err(AppError::conflict("This upload has already been processed")); }
    let expected_hash: String = row.try_get("secret_hash").map_err(AppError::database)?;

    let stage_filename = format!("{id}.{}.part", Uuid::new_v4());
    let stage_path = state.cfg.data_dir.join("staging").join(&stage_filename);
    let outcome: Result<(ArchiveInfo, String, u64), AppError> = async {
        let mut provided_secret = None::<String>;
        let mut saw_file = false;
        let mut size = 0u64;
        let mut sha = Sha256::new();
        while let Some(mut field) = multipart.next_field().await.map_err(|e| AppError::bad(format!("Malformed multipart request: {e}")))? {
            match field.name() {
                Some("upload_token") => {
                    if provided_secret.is_some() { return Err(AppError::bad("Duplicate upload_token")); }
                    provided_secret = Some(field.text().await.map_err(|_| AppError::bad("Invalid upload token field"))?);
                    if provided_secret.as_ref().is_none_or(|s| auth::hash_secret(s) != expected_hash) {
                        return Err(AppError::forbidden("Invalid or expired upload token"));
                    }
                }
                Some("file") => {
                    if saw_file { return Err(AppError::bad("Only one package archive is allowed")); }
                    if provided_secret.is_none() { return Err(AppError::bad("upload_token must come before file")); }
                    saw_file = true;
                    let mut file = fs::OpenOptions::new().write(true).create_new(true)
                        .open(&stage_path).await.map_err(AppError::io)?;
                    while let Some(chunk) = field.chunk().await.map_err(|e| AppError::bad(format!("Invalid archive body: {e}")))? {
                        size = size.saturating_add(chunk.len() as u64);
                        if size > state.cfg.max_upload_bytes as u64 {
                            return Err(AppError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "Package archive exceeds MAX_UPLOAD_MB"));
                        }
                        sha.update(&chunk);
                        file.write_all(&chunk).await.map_err(AppError::io)?;
                    }
                    file.flush().await.map_err(AppError::io)?;
                }
                _ => {} // Pub may add other, optional form fields.
            }
        }
        if !saw_file || size == 0 || provided_secret.is_none() {
            return Err(AppError::bad("Multipart must include upload_token and a nonempty file"));
        }
        let to_inspect = stage_path.clone();
        let max_unpacked = state.cfg.max_unpacked_bytes;
        let metadata = tokio::task::spawn_blocking(move || archive::inspect_archive(&to_inspect, max_unpacked))
            .await.map_err(AppError::io)?
            .map_err(AppError::bad)?;
        Ok((metadata, hex::encode(sha.finalize()), size))
    }.await;

    let (info, hash, size) = match outcome {
        Ok(result) => result,
        Err(err) => {
            let _ = fs::remove_file(&stage_path).await;
            return Err(err);
        }
    };
    let updated = sqlx::query("UPDATE upload_sessions SET status = 'staged', stage_filename = ?, package_name = ?, package_version = ?, pubspec_json = ?, archive_sha256 = ?, archive_size = ? WHERE id = ? AND status = 'initiated' AND expires_at > datetime('now')")
        .bind(&stage_filename).bind(&info.name).bind(&info.version)
        .bind(&info.pubspec_json).bind(&hash).bind(size as i64).bind(&id)
        .execute(&state.db).await;
    match updated {
        Ok(v) if v.rows_affected() == 1 => {}
        Ok(_) => {
            let _ = fs::remove_file(&stage_path).await;
            return Err(AppError::conflict("Upload ticket was already consumed or expired"));
        }
        Err(err) => {
            let _ = fs::remove_file(&stage_path).await;
            return Err(AppError::database(err));
        }
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    let location = format!("{}/api/uploads/{id}/finalize", state.cfg.base_url);
    response.headers_mut().insert(header::LOCATION, HeaderValue::from_str(&location).map_err(AppError::io)?);
    Ok(response)
}

pub(crate) async fn finalize(
    State(state): State<AppState>, Path(id): Path<String>, headers: HeaderMap,
) -> Result<Response, AppError> {
    if Uuid::parse_str(&id).is_err() { return Err(AppError::not_found()); }
    let publisher_hash = auth::require_token(&state, &headers, true).await?;
    let mut tx = state.db.begin().await.map_err(AppError::database)?;
    let row = sqlx::query("SELECT publisher_hash, status, expires_at, stage_filename, package_name, package_version, pubspec_json, archive_sha256, archive_size FROM upload_sessions WHERE id = ?")
        .bind(&id).fetch_optional(&mut *tx).await.map_err(AppError::database)?
        .ok_or_else(AppError::not_found)?;
    if row.try_get::<String,_>("publisher_hash").map_err(AppError::database)? != publisher_hash {
        return Err(AppError::forbidden("Upload belongs to a different publishing token"));
    }
    let status: String = row.try_get("status").map_err(AppError::database)?;
    if status == "published" {
        return Ok(pub_json(json!({"success": {"message": "Package was published successfully"}})));
    }
    if status != "staged" { return Err(AppError::bad("Archive must be uploaded before finalization")); }
    let unexpired = sqlx::query("SELECT 1 FROM upload_sessions WHERE id = ? AND expires_at > datetime('now')")
        .bind(&id).fetch_optional(&mut *tx).await.map_err(AppError::database)?;
    if unexpired.is_none() { return Err(AppError::bad("Upload ticket expired; publish again")); }
    let name: String = row.try_get("package_name").map_err(AppError::database)?;
    let version: String = row.try_get("package_version").map_err(AppError::database)?;
    verify_package_name(&name)?; verify_version(&version)?;
    let filename: String = row.try_get("stage_filename").map_err(AppError::database)?;
    let pubspec_json: String = row.try_get("pubspec_json").map_err(AppError::database)?;
    let sha: String = row.try_get("archive_sha256").map_err(AppError::database)?;
    let size: i64 = row.try_get("archive_size").map_err(AppError::database)?;

    let target = archive_path(&state, &name, &version);
    if sqlx::query("SELECT 1 FROM package_versions WHERE name = ? AND version = ?")
        .bind(&name).bind(&version).fetch_optional(&mut *tx).await.map_err(AppError::database)?.is_some()
        || fs::try_exists(&target).await.map_err(AppError::io)? {
        return Err(AppError::conflict(format!("{name} {version} is already published; versions are immutable")));
    }
    // The INSERT locks the SQLite writer before moving the archive into place.
    sqlx::query("INSERT INTO package_versions (name, version, pubspec_json, archive_sha256, archive_size) VALUES (?, ?, ?, ?, ?)")
        .bind(&name).bind(&version).bind(pubspec_json).bind(sha).bind(size)
        .execute(&mut *tx).await.map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.is_unique_violation() { return AppError::conflict("Package version already exists"); }
            }
            AppError::database(e)
        })?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).await.map_err(AppError::io)?;
    }
    let staged = state.cfg.data_dir.join("staging").join(filename);
    fs::rename(&staged, &target).await.map_err(AppError::io)?;
    if let Err(e) = sqlx::query("UPDATE upload_sessions SET status = 'published', stage_filename = NULL WHERE id = ?")
        .bind(&id).execute(&mut *tx).await {
        let _ = fs::rename(&target, &staged).await;
        return Err(AppError::database(e));
    }
    if let Err(e) = tx.commit().await {
        let _ = fs::rename(&target, &staged).await;
        return Err(AppError::database(e));
    }
    Ok(pub_json(json!({"success": {"message": format!("Successfully published {name} {version}")}})))
}
