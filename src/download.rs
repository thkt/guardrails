use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const OXLINT_VERSION: &str = "1.56.0";

const DOWNLOAD_BASE: &str = "https://github.com/oxc-project/oxc/releases/download";

fn detect_platform() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-gnu"),
        _ => None,
    }
}

fn download_url(version: &str, platform: &str) -> String {
    format!("{DOWNLOAD_BASE}/apps_v{version}/oxlint-{platform}.tar.gz")
}

fn default_cache_dir() -> Option<PathBuf> {
    let cache_base = std::env::var("XDG_CACHE_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".cache"))
        })?;
    Some(cache_base.join("guardrails/bin"))
}

pub fn ensure_oxlint() -> Option<PathBuf> {
    let cache = default_cache_dir()?;
    ensure_oxlint_with(&cache, fetch_url)
}

fn ensure_oxlint_with<F>(cache: &Path, fetch: F) -> Option<PathBuf>
where
    F: FnOnce(&str) -> Option<Vec<u8>>,
{
    let version = OXLINT_VERSION;
    let target = cache.join(format!("oxlint-{version}"));

    if target.exists() {
        return Some(target);
    }

    let platform = detect_platform().or_else(|| {
        eprintln!(
            "guardrails: unsupported platform for oxlint download (os={}, arch={})",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        None
    })?;

    let url = download_url(version, platform);
    let bytes = fetch(&url)?;
    extract_to_cache(&bytes, cache, version)
}

const MAX_DOWNLOAD_SIZE: u64 = 50_000_000;

fn fetch_url(url: &str) -> Option<Vec<u8>> {
    eprintln!("guardrails: downloading oxlint v{OXLINT_VERSION}...");
    let resp = ureq::get(url)
        .call()
        .map_err(|e| {
            eprintln!("guardrails: oxlint download failed: {e}");
        })
        .ok()?;

    let mut bytes = Vec::new();
    resp.into_reader()
        .take(MAX_DOWNLOAD_SIZE)
        .read_to_end(&mut bytes)
        .map_err(|e| {
            eprintln!("guardrails: oxlint download read error: {e}");
        })
        .ok()?;
    Some(bytes)
}

fn extract_to_cache(bytes: &[u8], cache: &Path, version: &str) -> Option<PathBuf> {
    fs::create_dir_all(cache)
        .map_err(|e| {
            eprintln!(
                "guardrails: failed to create cache dir {}: {e}",
                cache.display()
            )
        })
        .ok()?;

    let tar_path = cache.join(format!("oxlint-{version}.tar.gz"));
    let target = cache.join(format!("oxlint-{version}"));

    fs::write(&tar_path, bytes)
        .map_err(|e| {
            eprintln!(
                "guardrails: failed to write archive {}: {e}",
                tar_path.display()
            )
        })
        .ok()?;

    let output = crate::resolve::run_with_timeout(
        std::process::Command::new("tar")
            .args(["xzf"])
            .arg(&tar_path)
            .arg("-C")
            .arg(cache),
        "tar",
    );

    let _ = fs::remove_file(&tar_path);

    let output = output?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("guardrails: failed to extract oxlint archive: {stderr}");
        return None;
    }

    let extracted = cache.join("oxlint");
    if extracted != target {
        fs::rename(&extracted, &target)
            .map_err(|e| {
                eprintln!("guardrails: failed to rename oxlint binary: {e}");
                let _ = fs::remove_file(&extracted);
            })
            .ok()?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(&target, fs::Permissions::from_mode(0o755)) {
            eprintln!("guardrails: warning: failed to set executable permission: {e}");
        }
    }

    Some(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // T-014: platform detection on supported OS
    #[test]
    fn detect_platform_returns_known_triple() {
        let platform = detect_platform();
        assert!(platform.is_some(), "expected Some on macOS/Linux");
        let p = platform.unwrap();
        assert!(
            [
                "aarch64-apple-darwin",
                "x86_64-apple-darwin",
                "x86_64-unknown-linux-gnu",
                "aarch64-unknown-linux-gnu"
            ]
            .contains(&p),
            "unexpected platform: {p}"
        );
    }

    // T-014: darwin-arm64 URL construction
    #[test]
    fn download_url_darwin_arm64_has_correct_format() {
        assert_eq!(
            download_url("1.56.0", "aarch64-apple-darwin"),
            "https://github.com/oxc-project/oxc/releases/download/apps_v1.56.0/oxlint-aarch64-apple-darwin.tar.gz"
        );
    }

    // T-015: linux-x64 URL construction
    #[test]
    fn download_url_linux_x64_has_correct_format() {
        assert_eq!(
            download_url("1.56.0", "x86_64-unknown-linux-gnu"),
            "https://github.com/oxc-project/oxc/releases/download/apps_v1.56.0/oxlint-x86_64-unknown-linux-gnu.tar.gz"
        );
    }

    #[test]
    fn default_cache_dir_ends_with_guardrails_bin() {
        let dir = default_cache_dir();
        assert!(dir.is_some());
        assert!(dir.unwrap().ends_with("guardrails/bin"));
    }

    // T-003: cached binary exists → return without download
    #[test]
    fn returns_cached_binary() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join(format!("oxlint-{OXLINT_VERSION}"));
        fs::write(&bin, "fake").unwrap();

        let result = ensure_oxlint_with(tmp.path(), |_| panic!("should not download"));
        assert_eq!(result, Some(bin));
    }

    // T-005: network failure → None
    #[test]
    fn returns_none_on_fetch_failure() {
        let tmp = TempDir::new().unwrap();
        let result = ensure_oxlint_with(tmp.path(), |_| None);
        assert!(result.is_none());
    }

    // T-004: download + extract + cache
    #[test]
    fn downloads_extracts_and_caches() {
        let tmp = TempDir::new().unwrap();
        let staging = TempDir::new().unwrap();

        let dummy = staging.path().join("oxlint");
        fs::write(&dummy, "#!/bin/sh\necho test").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dummy, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let tar = staging.path().join("test.tar.gz");
        assert!(std::process::Command::new("tar")
            .args(["czf"])
            .arg(&tar)
            .arg("-C")
            .arg(staging.path())
            .arg("oxlint")
            .status()
            .unwrap()
            .success());
        let tar_bytes = fs::read(&tar).unwrap();

        let result = ensure_oxlint_with(tmp.path(), |_| Some(tar_bytes));
        assert!(result.is_some());

        let cached = result.unwrap();
        assert!(cached.exists());
        assert!(
            cached
                .to_str()
                .unwrap()
                .contains(&format!("oxlint-{OXLINT_VERSION}")),
            "cached path should contain versioned name"
        );
    }
}
