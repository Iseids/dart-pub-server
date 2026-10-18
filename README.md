# Dart Pub Server

Self-hosted **Dart / Flutter Pub package registry** written in **Rust + Tokio + Axum + SQLite**, deployable with **Docker Compose** and **Nginx**.

It implements the central parts of the [Hosted Pub Repository API v2](https://dart.googlesource.com/pub/+/refs/heads/master/doc/repository-spec-v2.md), including standard `dart pub publish` and hosted dependencies. No custom Dart tooling required.

**Features**

- Publish packages with normal `dart pub publish` (authenticated 3-step upload/finalize flow).
- Retrieve hosted packages with `dart pub get` and `flutter pub get`.
- Bearer tokens with `publish` or `read` roles, generated and revoked from the container CLI; only SHA-256 token hashes stored in SQLite.
- Optional private downloads (`PUBLIC_READS=false`); **downloads are public by default**, so restrict the Nginx hostname to your network/VPN or switch to private reads.
- SQLite WAL metadata, durable package archives on a persistent Docker volume, immutable package/version pairs.
- Validates gzip/tar, root `pubspec.yaml`, package name/version, upload size and uncompressed size; streams uploads to disk.
- Simple browser homepage with a package list, a basic `/api/search`, `GET /healthz`.
- Public URL configurable for HTTPS reverse proxy and optional Nginx subpath.

> **Deployment scope:** This is a lightweight, single-instance registry for a private network or small team, not a pub.dev mirror. It does **not** proxy third-party packages, implement package ownership per user, provide an authenticated browser admin panel, or accept Sigstore publishing attestations. Package archives are immutable once published. Treat the example as a starting point for production hardening, not an audited product.

## 1. Quick start with Docker Compose

Requirements: Docker Engine and `docker compose` v2, a server running Nginx, and a DNS name resolving to that server. The registry itself listens on port `8080` in Docker and is mapped **only to host localhost:8088**, so Nginx on the host can proxy it.

```bash
# Inside this project folder:
cp .env.example .env
nano .env
```

Replace `PUBLIC_BASE_URL=https://pub.example.com` with your **exact final** HTTPS URL (no trailing slash). This URL is embedded in package metadata and publishing redirects, so it must be reachable from every developer workstation and CI runner.

```bash
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:8088/healthz
```

Expected response: `{"status":"ok"}`.

You can open `https://pub.example.com` in your browser after configuring Nginx.

### Alternative: use a local LAN address

If the Nginx proxy is on a **different physical server**, either put both containers on a Docker network and proxy by service name (`http://registry:8080`), or explicitly expose `8088` on an address accessible to that Nginx host by changing the Compose port mapping. Firewall it to the Nginx server. Do not expose unauthenticated administrative interfaces. Use HTTPS for `dart pub token` / authenticated publishing; Dart deliberately limits use of tokens over plain HTTP.

## 2. Nginx + Let's Encrypt

This example assumes Nginx runs **on the host** and `pub.example.com` points to it. Replace the hostname and paths everywhere.

For a new hostname that has no certificate yet:

```bash
sudo cp nginx/pub-registry-http-bootstrap.conf /etc/nginx/sites-available/dart-pub-server
sudo sed -i 's/pub\.example\.com/your-pub-domain.example/g' /etc/nginx/sites-available/dart-pub-server
sudo ln -s /etc/nginx/sites-available/dart-pub-server /etc/nginx/sites-enabled/dart-pub-server
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d your-pub-domain.example
```

Certbot's Nginx plugin obtains a certificate and can install a working HTTPS block. You can keep that configuration, or switch to the supplied HTTPS template:

```bash
# Optional: replace the Certbot-generated config with the hardened example.
sudo cp nginx/pub-registry.conf /etc/nginx/sites-available/dart-pub-server
sudo sed -i 's/pub\.example\.com/your-pub-domain.example/g' /etc/nginx/sites-available/dart-pub-server
sudo nginx -t && sudo systemctl reload nginx
```

Set `.env` accordingly:

```dotenv
PUBLIC_BASE_URL=https://your-pub-domain.example
```

Then run `docker compose up -d` to apply the new URL, and test:

```bash
curl -fsS https://your-pub-domain.example/healthz
```

**Nginx details:** `client_max_body_size 40m` accommodates the default `MAX_UPLOAD_MB=32`. Increase both for larger packages. Keep the `Authorization` header forwarding, `proxy_request_buffering off`, and timeouts. For self-signed/local-CA TLS, install/trust your CA on all Dart/Flutter clients.

### Optional: Nginx subpath

For `https://example.com/dart-pub` instead of a dedicated hostname, set:

```dotenv
PUBLIC_BASE_URL=https://example.com/dart-pub
```

Configure Nginx with the trailing slashes shown below to strip `/dart-pub/` before forwarding to Axum:

```nginx
location = /dart-pub { return 301 /dart-pub/; }
location /dart-pub/ {
    client_max_body_size 40m;
    proxy_pass http://127.0.0.1:8088/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Authorization $http_authorization;
    proxy_request_buffering off;
}
```

Set `publish_to`, `hosted`, and `dart pub token add` to the **same exact base URL including the subpath**.

## 3. Create a publishing token

```bash
# Default role is 'publish'. The token is printed ONLY on creation.
docker compose exec registry pub-registry token create my-laptop publish

# Manage existing tokens (values are never revealed again):
docker compose exec registry pub-registry token list
docker compose exec registry pub-registry token revoke my-laptop

# Optional read-only CI/developer token:
docker compose exec registry pub-registry token create build-agent read
```

On the workstation containing the Dart SDK:

```bash
dart pub token add https://your-pub-domain.example
# Paste the token at the prompt. The secret is not placed in shell history.
```

For CI, store the secret in a CI secret variable and run:

```bash
dart pub token add https://your-pub-domain.example --env-var PUB_REGISTRY_TOKEN
```

Tokens work only when Dart considers the registry URL safe for authentication (HTTPS). With `PUBLIC_READS=true`, downloads don't require tokens; publishing always does. With `PUBLIC_READS=false`, users/CI must configure a `read` or `publish` token to resolve dependencies.

## 4. Publish a Dart or Flutter package

In the **package to be published**, set the public registry URL and a new semantic version:

```yaml
name: my_shared_package
version: 1.0.0
description: Internal shared utilities for our Dart and Flutter applications.
environment:
  sdk: ^3.0.0
publish_to: https://your-pub-domain.example
```

Then run:

```bash
cd path/to/my_shared_package
dart pub publish --dry-run
dart pub publish
```

Flutter package developers can also use `flutter pub publish`. The archive contains the root `pubspec.yaml`; the registry checks the package name and version and never replaces an existing version. Increment the version to publish updates.

A ready-to-edit sample package is in `../../Downloads/Dart_Pub_Server (2)/Dart_Pub_Server/examples/hello_private`.

## 5. Consume a private package

In any other Dart/Flutter project, add a *hosted* dependency:

```yaml
dependencies:
  my_shared_package:
    hosted: https://your-pub-domain.example
    version: ^1.0.0
```

Run:

```bash
dart pub get
# or, for Flutter:
flutter pub get
```

This leaves all other packages (such as `http`, `flutter_riverpod`, etc.) on **pub.dev**, avoiding an unwanted global repository override. Don't set `PUB_HOSTED_URL` globally unless you intentionally host or mirror *all* package dependencies (this registry does not mirror pub.dev).

## 6. Useful API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Package dashboard (public, or hidden list in private mode) |
| GET | `/healthz` | Health + SQLite connectivity |
| GET | `/api/search?q=foo` | Search local package names |
| GET | `/api/packages/my_shared_package` | List Pub v2 version metadata |
| GET | `/api/packages/my_shared_package/versions/1.0.0` | Specific version (older Pub clients) |
| GET | `/packages/my_shared_package/versions/1.0.0.tar.gz` | Archive bytes |
| GET | `/api/packages/versions/new` | Authenticated publishing handshake |
| POST | `/api/uploads/{id}` | One-time multipart upload, using returned form token |
| GET | `/api/uploads/{id}/finalize` | Authenticated commit and success response |

`archive_url` values are always absolute and include the configured `PUBLIC_BASE_URL`; `archive_sha256` is returned for integrity verification. The API has Pub v2 JSON success/error response types and correctly emits `401` for invalid credentials versus `403` for insufficient role.

### Quick health checks

```bash
./scripts/smoke.sh https://your-pub-domain.example
curl -s https://your-pub-domain.example/api/search?q=my_shared_package
curl -s https://your-pub-domain.example/api/packages/my_shared_package
```

For a complete end-to-end check, edit `../../Downloads/Dart_Pub_Server (2)/Dart_Pub_Server/examples/hello_private/pubspec.yaml`, create a publishing token, run `dart pub publish` there, then edit `examples/consumer/pubspec.yaml` and run `dart pub get` in the consumer folder.

## 7. Operations and backup

- Docker volume `pub_registry_data` stores **both** the database (`registry.db` and WAL files) and package archives. Never delete the volume unless you deliberately want to delete the registry.
- To upgrade after editing: `docker compose up -d --build` (SQLite migrations run at startup).
- For consistent backups, stop the registry, then copy/snapshot the entire named volume, and restart. `docker volume ls` reveals the actual Compose-generated volume name (usually `<project>_pub_registry_data`). Example with your actual volume name:

```bash
docker compose stop registry
mkdir -p backups
docker run --rm -v YOUR_VOLUME_NAME:/data:ro -v "$PWD/backups:/backup" alpine:3.21 \
  tar -czf /backup/dart-pub-registry-backup.tar.gz -C /data .
docker compose start registry
```

- Protect backups because private package code and registry access data are included. Backup before upgrades, test restoration, and restrict access to the Docker host and its volume.
- One server instance per SQLite database/volume. Do **not** horizontally scale this service across multiple hosts sharing an SQLite database or archive directory; for HA, use a database/object-storage design.
- Upload tickets expire after 30 minutes. A maintenance loop runs hourly to remove expired sessions and orphaned staging files. Retain published archive contents.
- Packages remain downloadable even if the publishing token is subsequently revoked.

## 8. Developing without Docker

If you have a Rust toolchain installed:

```bash
cp .env.example .env
# For local non-publishing API tests only, use localhost:
# Set PUBLIC_BASE_URL=http://localhost:8088 in .env
mkdir -p data
cargo test
cargo run -- serve
# another terminal: cargo run -- token create local-dev
```

The database URL defaults to `sqlite://./data/registry.db` when running directly. `cargo test` checks archive validation. Rust 2024 edition and current stable Rust are expected.

## Security model and known limitations

- The server validates uploads and stores only hashes of long random bearer tokens, but does not include rate limits, external identity/SSO, or fine-grained per-package authorization. Nginx allowlisting, a VPN, and/or a small trusted team are appropriate controls.
- Archive uploads are limited to 32 MiB compressed by default and 256 MiB unpacked, with a 1 MiB pubspec limit. The file is validated without extracting it onto disk.
- The official Pub protocol supports optional supply-chain attestations. This server does **not** advertise attestation support or accept attestation uploads; a client requiring an attestation will be unable to publish.
- The registry does not host arbitrary files, mirror pub.dev, offer package removal, generate hosted docs, or automatically flag OSV security advisories.
- For safe package distribution, use trusted HTTPS in Nginx. `PUBLIC_BASE_URL` must always match the actual external URL. Publishing over HTTP using `dart pub token` is intentionally unsupported by the Dart client.

## Compatibility reference

- [Dart — Custom package repositories](https://dart.dev/tools/pub/custom-package-repositories)
- [Dart — Pub token management](https://dart.dev/tools/pub/cmd/pub-token)
- [Dart — Hosted Pub Repository Specification V2](https://dart.googlesource.com/pub/+/refs/heads/publish-with-attestation/doc/repository-spec-v2.md)
