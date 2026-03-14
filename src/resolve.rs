use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

pub fn is_tool_available(name: &str, file_path: &str) -> bool {
    Command::new(resolve_bin(name, file_path))
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

const LINTER_TIMEOUT: Duration = Duration::from_secs(5);

pub fn run_with_timeout(cmd: &mut Command, tool: &str) -> Option<Output> {
    let mut child = match cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("guardrails: {}: failed to spawn: {}", tool, e);
            return None;
        }
    };

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|e| {
                        eprintln!("guardrails: {}: failed to collect output: {}", tool, e);
                        e
                    })
                    .ok();
            }
            Ok(None) => {
                if start.elapsed() > LINTER_TIMEOUT {
                    eprintln!(
                        "guardrails: {}: timed out after {}s, skipping",
                        tool,
                        LINTER_TIMEOUT.as_secs()
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                eprintln!("guardrails: {}: process error: {}", tool, e);
                return None;
            }
        }
    }
}

/// Falls back to bare command name (PATH resolution) if not found in node_modules.
pub fn resolve_bin(name: &str, file_path: &str) -> PathBuf {
    let mut dir = Path::new(file_path).parent();
    while let Some(d) = dir {
        let candidate = d.join("node_modules/.bin").join(name);
        if candidate.exists() {
            return candidate;
        }
        dir = d.parent();
    }
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn finds_bin_in_direct_parent_node_modules() {
        let tmp = TempDir::new().unwrap();
        let bin_dir = tmp.path().join("node_modules/.bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let bin_path = bin_dir.join("oxlint");
        fs::write(&bin_path, "").unwrap();

        let file_path = tmp.path().join("src/app.ts");
        let result = resolve_bin("oxlint", file_path.to_str().unwrap());
        assert_eq!(result, bin_path);
    }

    #[test]
    fn walks_up_to_find_node_modules() {
        let tmp = TempDir::new().unwrap();
        let bin_dir = tmp.path().join("node_modules/.bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let bin_path = bin_dir.join("biome");
        fs::write(&bin_path, "").unwrap();

        let deep_dir = tmp.path().join("src/components");
        fs::create_dir_all(&deep_dir).unwrap();
        let file_path = deep_dir.join("Button.tsx");

        let result = resolve_bin("biome", file_path.to_str().unwrap());
        assert_eq!(result, bin_path);
    }

    #[test]
    fn falls_back_to_bare_name_when_not_in_node_modules() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("test.ts");

        let result = resolve_bin("oxlint", file_path.to_str().unwrap());
        assert_eq!(result, PathBuf::from("oxlint"));
    }

    #[test]
    fn prefers_closest_node_modules() {
        let tmp = TempDir::new().unwrap();

        // root node_modules
        let root_bin = tmp.path().join("node_modules/.bin");
        fs::create_dir_all(&root_bin).unwrap();
        fs::write(root_bin.join("oxlint"), "root").unwrap();

        // nested packages/app/node_modules (monorepo)
        let nested_bin = tmp.path().join("packages/app/node_modules/.bin");
        fs::create_dir_all(&nested_bin).unwrap();
        fs::write(nested_bin.join("oxlint"), "nested").unwrap();

        let file_path = tmp.path().join("packages/app/src/index.ts");
        let result = resolve_bin("oxlint", file_path.to_str().unwrap());
        assert_eq!(result, nested_bin.join("oxlint"));
    }
}
