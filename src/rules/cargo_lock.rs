use super::{Rule, Severity, Violation, RE_ALL_FILES};

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_ALL_FILES.clone(),
        checker: Box::new(|_content: &str, file_path: &str| {
            let name = file_path
                .rsplit(&['/', '\\'][..])
                .next()
                .unwrap_or(file_path);
            if name == "Cargo.lock" {
                return vec![Violation {
                    rule: super::rule_id::CARGO_LOCK.to_string(),
                    severity: Severity::Critical,
                    failure:
                        "Do not directly edit Cargo.lock. Modify Cargo.toml and run cargo update."
                            .to_string(),
                    file: file_path.to_string(),
                    line: None,
                }];
            }
            Vec::new()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(path: &str) -> Vec<Violation> {
        rule().check("", path)
    }

    #[test]
    fn detects_cargo_lock() {
        assert_eq!(check("Cargo.lock").len(), 1);
        assert_eq!(check("/project/Cargo.lock").len(), 1);
    }

    #[test]
    fn allows_cargo_toml() {
        assert!(check("Cargo.toml").is_empty());
    }

    #[test]
    fn allows_normal_files() {
        assert!(check("src/main.rs").is_empty());
    }

    #[test]
    fn detects_cargo_lock_windows_path() {
        let rule = rule();
        let result = rule.check("", r"C:\project\Cargo.lock");
        assert_eq!(result.len(), 1);
    }
}
