use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const LINTER_TIMEOUT: Duration = Duration::from_secs(5);

pub fn run_with_timeout(cmd: &mut Command, tool: &str) -> Option<Output> {
    let mut child = match cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("guardrails: {}: failed to spawn: {}", tool, e);
            return None;
        }
    };

    let child_pid = child.id();

    let mut stdout = child.stdout.take()?;
    let mut stderr = child.stderr.take()?;
    let out_t = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let err_t = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        buf
    });

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait());
    });

    let status = match rx.recv_timeout(LINTER_TIMEOUT) {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            eprintln!("guardrails: {}: process error: {}", tool, e);
            return None;
        }
        Err(_) => {
            eprintln!(
                "guardrails: {}: timed out after {}s, skipping",
                tool,
                LINTER_TIMEOUT.as_secs()
            );
            let _ = Command::new("kill")
                .args(["-9", &child_pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            return None;
        }
    };

    Some(Output {
        status,
        stdout: out_t.join().unwrap_or_else(|_| {
            eprintln!("guardrails: {tool}: stdout reader thread panicked");
            Vec::new()
        }),
        stderr: err_t.join().unwrap_or_else(|_| {
            eprintln!("guardrails: {tool}: stderr reader thread panicked");
            Vec::new()
        }),
    })
}

/// Resolves a tool binary, checking node_modules first, then PATH.
pub fn try_resolve_bin(name: &str, file_path: &str) -> Option<PathBuf> {
    let mut dir = Path::new(file_path).parent();
    while let Some(d) = dir {
        let candidate = d.join("node_modules/.bin").join(name);
        if candidate.exists() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    std::env::var("PATH").ok().and_then(|path_var| {
        std::env::split_paths(&path_var)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.exists())
    })
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
        let result = try_resolve_bin("oxlint", file_path.to_str().unwrap());
        assert_eq!(result, Some(bin_path));
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

        let result = try_resolve_bin("biome", file_path.to_str().unwrap());
        assert_eq!(result, Some(bin_path));
    }

    #[test]
    fn returns_none_when_not_found() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("test.ts");

        let result = try_resolve_bin("nonexistent_tool_xyz", file_path.to_str().unwrap());
        assert_eq!(result, None);
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
        let result = try_resolve_bin("oxlint", file_path.to_str().unwrap());
        assert_eq!(result, Some(nested_bin.join("oxlint")));
    }
}
