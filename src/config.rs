use crate::rules::Severity;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub enabled: bool,
    pub rules: RulesConfig,
    pub severity: SeverityConfig,
}

#[derive(Debug, Clone)]
pub struct RulesConfig {
    pub sensitive_file: bool,
    pub architecture: bool,
    pub naming: bool,
    pub transaction: bool,
    pub security: bool,
    pub crypto_weak: bool,
    pub generated_file: bool,
    pub test_location: bool,
    pub dom_access: bool,
    pub sync_io: bool,
    pub bundle_size: bool,
    pub test_assertion: bool,
    pub flaky_test: bool,
    pub sensitive_logging: bool,
    pub biome: bool,
    pub oxlint: bool,
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            sensitive_file: true,
            architecture: true,
            naming: true,
            transaction: true,
            security: true,
            crypto_weak: true,
            generated_file: true,
            test_location: true,
            dom_access: true,
            sync_io: true,
            bundle_size: true,
            test_assertion: true,
            flaky_test: true,
            sensitive_logging: true,
            biome: true,
            oxlint: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SeverityConfig {
    pub block_on: Vec<Severity>,
}

fn default_block_on() -> Vec<Severity> {
    vec![Severity::Critical, Severity::High]
}

impl Default for SeverityConfig {
    fn default() -> Self {
        Self {
            block_on: default_block_on(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: true,
            rules: RulesConfig::default(),
            severity: SeverityConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ProjectConfig {
    enabled: Option<bool>,
    rules: Option<ProjectRulesConfig>,
    severity: Option<ProjectSeverityConfig>,
}

#[derive(Debug, Deserialize)]
struct ProjectRulesConfig {
    #[serde(rename = "sensitiveFile")]
    sensitive_file: Option<bool>,
    architecture: Option<bool>,
    naming: Option<bool>,
    transaction: Option<bool>,
    security: Option<bool>,
    #[serde(rename = "cryptoWeak")]
    crypto_weak: Option<bool>,
    #[serde(rename = "generatedFile")]
    generated_file: Option<bool>,
    #[serde(rename = "testLocation")]
    test_location: Option<bool>,
    #[serde(rename = "domAccess")]
    dom_access: Option<bool>,
    #[serde(rename = "syncIo")]
    sync_io: Option<bool>,
    #[serde(rename = "bundleSize")]
    bundle_size: Option<bool>,
    #[serde(rename = "testAssertion")]
    test_assertion: Option<bool>,
    #[serde(rename = "flakyTest")]
    flaky_test: Option<bool>,
    #[serde(rename = "sensitiveLogging")]
    sensitive_logging: Option<bool>,
    biome: Option<bool>,
    oxlint: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ProjectSeverityConfig {
    #[serde(rename = "blockOn")]
    block_on: Option<Vec<Severity>>,
}

const PROJECT_CONFIG_FILE: &str = ".claude-guardrails.json";

impl Config {
    /// Merge project-local `.claude-guardrails.json` overrides from the .git root.
    pub fn with_project_overrides(self, file_path: &str) -> Self {
        let Some(config_path) = Self::find_project_config(file_path) else {
            return self;
        };

        let content = match fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "guardrails: warning: cannot read project config {:?}: {}",
                    config_path, e
                );
                return self;
            }
        };

        match serde_json::from_str::<ProjectConfig>(&content) {
            Ok(project) => self.merge(project),
            Err(e) => {
                eprintln!(
                    "guardrails: warning: invalid project config {:?}: {}",
                    config_path, e
                );
                self
            }
        }
    }

    fn merge(mut self, project: ProjectConfig) -> Self {
        if let Some(enabled) = project.enabled {
            self.enabled = enabled;
        }
        if let Some(pr) = project.rules {
            let r = &mut self.rules;
            macro_rules! override_field {
                ($field:ident) => {
                    if let Some(v) = pr.$field {
                        r.$field = v;
                    }
                };
            }
            override_field!(sensitive_file);
            override_field!(architecture);
            override_field!(naming);
            override_field!(transaction);
            override_field!(security);
            override_field!(crypto_weak);
            override_field!(generated_file);
            override_field!(test_location);
            override_field!(dom_access);
            override_field!(sync_io);
            override_field!(bundle_size);
            override_field!(test_assertion);
            override_field!(flaky_test);
            override_field!(sensitive_logging);
            override_field!(biome);
            override_field!(oxlint);
        }
        if let Some(ps) = project.severity {
            if let Some(block_on) = ps.block_on {
                self.severity.block_on = block_on;
            }
        }
        self
    }

    fn find_project_config(file_path: &str) -> Option<PathBuf> {
        let mut dir = std::path::Path::new(file_path).parent();
        while let Some(d) = dir {
            if d.join(".git").exists() {
                let candidate = d.join(PROJECT_CONFIG_FILE);
                if candidate.exists() {
                    return Some(candidate);
                }
                return None;
            }
            dir = d.parent();
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn default_config_all_rules_enabled() {
        let config = Config::default();
        assert!(config.enabled);
        assert!(config.rules.sensitive_file);
        assert!(config.rules.biome);
        assert!(config.rules.oxlint);
    }

    #[test]
    fn default_severity_blocks_critical_and_high() {
        let config = Config::default();
        assert!(config.severity.block_on.contains(&Severity::Critical));
        assert!(config.severity.block_on.contains(&Severity::High));
        assert!(!config.severity.block_on.contains(&Severity::Medium));
    }

    // --- Project config tests ---

    #[test]
    fn find_project_config_at_git_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();
        fs::write(
            tmp.path().join(PROJECT_CONFIG_FILE),
            r#"{"rules":{"biome":false}}"#,
        )
        .unwrap();
        let deep = tmp.path().join("src/components");
        fs::create_dir_all(&deep).unwrap();

        let file_path = deep.join("Button.tsx");
        let result = Config::find_project_config(file_path.to_str().unwrap());
        assert_eq!(result, Some(tmp.path().join(PROJECT_CONFIG_FILE)));
    }

    #[test]
    fn find_project_config_none_without_git() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::write(
            tmp.path().join(PROJECT_CONFIG_FILE),
            r#"{"rules":{"biome":false}}"#,
        )
        .unwrap();

        let file_path = tmp.path().join("src/app.ts");
        assert_eq!(Config::find_project_config(file_path.to_str().unwrap()), None);
    }

    #[test]
    fn find_project_config_none_when_git_but_no_config() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();

        let file_path = tmp.path().join("src/app.ts");
        assert_eq!(Config::find_project_config(file_path.to_str().unwrap()), None);
    }

    #[test]
    fn merge_partial_rules_override() {
        let base = Config::default();
        let project: ProjectConfig = serde_json::from_str(
            r#"{"rules": {"biome": false, "oxlint": false}}"#,
        )
        .unwrap();

        let merged = base.merge(project);
        assert!(!merged.rules.biome);
        assert!(!merged.rules.oxlint);
        // Unspecified rules keep defaults
        assert!(merged.rules.sensitive_file);
        assert!(merged.rules.security);
    }

    #[test]
    fn merge_enabled_override() {
        let base = Config::default();
        let project: ProjectConfig =
            serde_json::from_str(r#"{"enabled": false}"#).unwrap();

        let merged = base.merge(project);
        assert!(!merged.enabled);
        assert!(merged.rules.sensitive_file);
    }

    #[test]
    fn merge_severity_override() {
        let base = Config::default();
        let project: ProjectConfig = serde_json::from_str(
            r#"{"severity": {"blockOn": ["critical"]}}"#,
        )
        .unwrap();

        let merged = base.merge(project);
        assert_eq!(merged.severity.block_on, vec![Severity::Critical]);
    }

    #[test]
    fn merge_empty_project_config_no_change() {
        let base = Config::default();
        let project: ProjectConfig = serde_json::from_str(r#"{}"#).unwrap();

        let merged = base.merge(project);
        assert!(merged.enabled);
        assert!(merged.rules.biome);
        assert!(merged.rules.oxlint);
        assert_eq!(merged.severity.block_on.len(), 2);
    }

    #[test]
    fn with_project_overrides_applies_config() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();
        fs::write(
            tmp.path().join(PROJECT_CONFIG_FILE),
            r#"{"rules": {"biome": false}}"#,
        )
        .unwrap();

        let file_path = tmp.path().join("src/app.ts");
        let config = Config::default().with_project_overrides(file_path.to_str().unwrap());
        assert!(!config.rules.biome);
        assert!(config.rules.oxlint);
    }

    #[test]
    fn with_project_overrides_no_config_returns_unchanged() {
        let tmp = tempfile::TempDir::new().unwrap();

        let file_path = tmp.path().join("src/app.ts");
        let config = Config::default().with_project_overrides(file_path.to_str().unwrap());
        assert!(config.rules.biome);
        assert!(config.rules.oxlint);
    }

    #[test]
    fn with_project_overrides_malformed_json_returns_unchanged() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();
        fs::write(tmp.path().join(PROJECT_CONFIG_FILE), "not valid json{{{").unwrap();

        let file_path = tmp.path().join("src/app.ts");
        let config = Config::default().with_project_overrides(file_path.to_str().unwrap());
        assert!(config.enabled);
        assert!(config.rules.sensitive_file);
    }
}
