use std::path::{Path, PathBuf};

/// Search for a binary in node_modules/.bin/ walking up from file_path,
/// then fall back to the bare command name (PATH resolution).
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
