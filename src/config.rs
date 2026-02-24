use crate::rules::Severity;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

macro_rules! define_rule_config {
    ($( $field:ident => $serde_name:literal ),* $(,)?) => {
        #[derive(Debug, Clone)]
        pub struct RulesConfig {
            $(pub $field: bool,)*
        }

        impl Default for RulesConfig {
            fn default() -> Self {
                Self { $($field: true,)* }
            }
        }

        #[derive(Debug, Deserialize)]
        struct ProjectRulesConfig {
            $(
                #[serde(rename = $serde_name)]
                $field: Option<bool>,
            )*
        }

        impl RulesConfig {
            fn apply_overrides(&mut self, project: ProjectRulesConfig) {
                $(if let Some(v) = project.$field { self.$field = v; })*
            }
        }
    };
}

define_rule_config! {
    sensitive_file    => "sensitiveFile",
    architecture      => "architecture",
    naming            => "naming",
    transaction       => "transaction",
    security          => "security",
    crypto_weak       => "cryptoWeak",
    generated_file    => "generatedFile",
    test_location     => "testLocation",
    dom_access        => "domAccess",
    sync_io           => "syncIo",
    bundle_size       => "bundleSize",
    test_assertion    => "testAssertion",
    flaky_test        => "flakyTest",
    sensitive_logging => "sensitiveLogging",
    biome             => "biome",
    oxlint            => "oxlint",
    eval              => "eval",
    hardcoded_secrets => "hardcodedSecrets",
    http_resource     => "httpResource",
    raw_html          => "rawHtml",
    open_redirect     => "openRedirect",
}

#[derive(Debug, Clone)]
pub struct Config {
    pub enabled: bool,
    pub rules: RulesConfig,
    pub severity: SeverityConfig,
}

#[derive(Debug, Clone)]
pub struct SeverityConfig {
    pub block_on: Vec<Severity>,
}

impl Default for SeverityConfig {
    fn default() -> Self {
        Self {
            block_on: vec![Severity::Critical, Severity::High],
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
struct ProjectSeverityConfig {
    #[serde(rename = "blockOn")]
    block_on: Option<Vec<Severity>>,
}

const PROJECT_CONFIG_FILE: &str = ".claude-guardrails.json";

impl Config {
    pub fn with_project_overrides(self, file_path: &str) -> Result<Self, String> {
        let Some(config_path) = Self::find_project_config(file_path) else {
            return Ok(self);
        };

        let content = fs::read_to_string(&config_path)
            .map_err(|e| format!("cannot read project config {:?}: {}", config_path, e))?;

        let project: ProjectConfig = serde_json::from_str(&content)
            .map_err(|e| format!("invalid project config {:?}: {}", config_path, e))?;

        Ok(self.merge(project))
    }

    fn merge(mut self, project: ProjectConfig) -> Self {
        if let Some(enabled) = project.enabled {
            self.enabled = enabled;
        }
        if let Some(pr) = project.rules {
            self.rules.apply_overrides(pr);
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
        assert_eq!(
            Config::find_project_config(file_path.to_str().unwrap()),
            None
        );
    }

    #[test]
    fn find_project_config_none_when_git_but_no_config() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();

        let file_path = tmp.path().join("src/app.ts");
        assert_eq!(
            Config::find_project_config(file_path.to_str().unwrap()),
            None
        );
    }

    #[test]
    fn merge_partial_rules_override() {
        let base = Config::default();
        let project: ProjectConfig =
            serde_json::from_str(r#"{"rules": {"biome": false, "oxlint": false}}"#).unwrap();

        let merged = base.merge(project);
        assert!(!merged.rules.biome);
        assert!(!merged.rules.oxlint);
        assert!(merged.rules.sensitive_file);
        assert!(merged.rules.security);
    }

    #[test]
    fn merge_enabled_override() {
        let base = Config::default();
        let project: ProjectConfig = serde_json::from_str(r#"{"enabled": false}"#).unwrap();

        let merged = base.merge(project);
        assert!(!merged.enabled);
        assert!(merged.rules.sensitive_file);
    }

    #[test]
    fn merge_severity_override() {
        let base = Config::default();
        let project: ProjectConfig =
            serde_json::from_str(r#"{"severity": {"blockOn": ["critical"]}}"#).unwrap();

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
        let config = Config::default()
            .with_project_overrides(file_path.to_str().unwrap())
            .unwrap();
        assert!(!config.rules.biome);
        assert!(config.rules.oxlint);
    }

    #[test]
    fn with_project_overrides_no_config_returns_unchanged() {
        let tmp = tempfile::TempDir::new().unwrap();

        let file_path = tmp.path().join("src/app.ts");
        let config = Config::default()
            .with_project_overrides(file_path.to_str().unwrap())
            .unwrap();
        assert!(config.rules.biome);
        assert!(config.rules.oxlint);
    }

    #[test]
    fn with_project_overrides_malformed_json_returns_error() {
        let tmp = tempfile::TempDir::new().unwrap();
        fs::create_dir(tmp.path().join(".git")).unwrap();
        fs::write(tmp.path().join(PROJECT_CONFIG_FILE), "not valid json{{{").unwrap();

        let file_path = tmp.path().join("src/app.ts");
        let result = Config::default().with_project_overrides(file_path.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid project config"));
    }
}
