use std::{fs::File, io::Read, path::{Component, Path}};

use flate2::read::GzDecoder;
use semver::Version;
use serde_json::Value;
use tar::Archive;

pub(crate) struct ArchiveInfo {
    pub name: String,
    pub version: String,
    pub pubspec_json: String,
}

pub(crate) fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('a'..='z'))
        && name.len() <= 128
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

pub(crate) fn valid_version(version: &str) -> bool {
    version.len() <= 128 && Version::parse(version).is_ok()
}

pub(crate) fn inspect_archive(path: &Path, max_unpacked: u64) -> Result<ArchiveInfo, String> {
    let file = File::open(path).map_err(|e| format!("Could not open uploaded archive: {e}"))?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    let mut pubspec_bytes: Option<Vec<u8>> = None;
    let mut unpacked = 0u64;
    let mut entry_count = 0u32;

    for result in archive.entries().map_err(|e| format!("Invalid gzip/tar archive: {e}"))? {
        let mut entry = result.map_err(|e| format!("Invalid tar entry: {e}"))?;
        entry_count += 1;
        if entry_count > 20_000 { return Err("Archive has too many entries".into()); }
        let path = entry.path().map_err(|e| format!("Invalid entry path: {e}"))?;
        if path.components().any(|part| !matches!(part, Component::Normal(_) | Component::CurDir)) {
            return Err("Archive contains an unsafe file path".into());
        }
        let root_pubspec = path.components().filter(|p| matches!(p, Component::Normal(_)))
            .count() == 1 && path.file_name().is_some_and(|s| s == "pubspec.yaml");
        drop(path);

        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            return Err("Archive contains a symlink or unsupported tar entry".into());
        }
        unpacked = unpacked.checked_add(entry.size())
            .ok_or_else(|| "Archive is too large".to_string())?;
        if unpacked > max_unpacked { return Err("Uncompressed package exceeds the size limit".into()); }

        if root_pubspec {
            if pubspec_bytes.is_some() { return Err("Archive contains multiple root pubspec.yaml files".into()); }
            if !kind.is_file() || entry.size() > 1024 * 1024 {
                return Err("pubspec.yaml must be a file smaller than 1 MiB".into());
            }
            let mut content = Vec::new();
            entry.read_to_end(&mut content).map_err(|e| format!("Cannot read pubspec.yaml: {e}"))?;
            pubspec_bytes = Some(content);
        }
    }

    let bytes = pubspec_bytes.ok_or_else(|| "Archive must include pubspec.yaml at its root".to_string())?;
    let pubspec: Value = serde_yaml::from_slice(&bytes)
        .map_err(|e| format!("Malformed pubspec.yaml: {e}"))?;
    let name = pubspec.get("name").and_then(Value::as_str)
        .ok_or("pubspec.yaml has no name")?.to_string();
    let version = pubspec.get("version").and_then(Value::as_str)
        .ok_or("pubspec.yaml has no version")?.to_string();
    if !valid_name(&name) { return Err("Invalid Dart package name (use lowercase letters, numbers, underscores; start with a letter)".into()); }
    if !valid_version(&version) { return Err("Invalid semantic version in pubspec.yaml".into()); }

    Ok(ArchiveInfo {
        name,
        version,
        pubspec_json: serde_json::to_string(&pubspec).map_err(|e| e.to_string())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn example_archive(contents: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        let gz = flate2::write::GzEncoder::new(file.reopen().unwrap(), flate2::Compression::default());
        let mut tar = tar::Builder::new(gz);
        let bytes = contents.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_path("pubspec.yaml").unwrap();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, bytes).unwrap();
        tar.finish().unwrap();
        let mut gz = tar.into_inner().unwrap();
        gz.flush().unwrap();
        gz.finish().unwrap();
        file
    }

    #[test]
    fn recognizes_valid_pub_archive() {
        let archive = example_archive("name: test_package\nversion: 1.0.0+2\ndescription: Hello\n");
        let info = inspect_archive(archive.path(), 1024 * 1024).unwrap();
        assert_eq!(info.name, "test_package");
        assert_eq!(info.version, "1.0.0+2");
    }

    #[test]
    fn rejects_bad_name() {
        let archive = example_archive("name: Bad-Package\nversion: 1.0.0\n");
        assert!(inspect_archive(archive.path(), 1024 * 1024).is_err());
    }
}
