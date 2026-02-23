use super::{non_comment_lines, Rule, Severity, Violation, RE_ALL_FILES};
use once_cell::sync::Lazy;
use regex::Regex;

// Known secret prefixes (INT-009: extended with Slack, GitLab, Stripe, SendGrid)
static RE_KNOWN_PREFIX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"["'](sk-[a-zA-Z0-9]{10,}|AKIA[A-Z0-9]{12,}|ghp_[a-zA-Z0-9]{10,}|gho_[a-zA-Z0-9]{10,}|ghs_[a-zA-Z0-9]{10,}|xoxb-[a-zA-Z0-9]{10,}|xoxp-[a-zA-Z0-9]{10,}|glpat-[a-zA-Z0-9]{10,}|sk_live_[a-zA-Z0-9]{10,}|rk_live_[a-zA-Z0-9]{10,}|SG\.[a-zA-Z0-9]{10,})["']"#,
    )
    .expect("RE_KNOWN_PREFIX: invalid regex")
});

// Bearer/Basic token pattern: "Bearer <token>" with token length >= 20
static RE_BEARER_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"["'](Bearer|Basic)\s+[A-Za-z0-9._+/=-]{20,}["']"#)
        .expect("RE_BEARER_TOKEN: invalid regex")
});

// AWS access key pattern (standalone, not inside quotes — for direct assignment)
static RE_AWS_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["'][A-Za-z0-9/+=]{16,}["']"#,
    )
    .expect("RE_AWS_KEY: invalid regex")
});

// Password/secret variable assignment: password = "...", secret = "..."
// Requires value length >= 4 to reduce false positives (SEC-004)
static RE_PASSWORD_ASSIGN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)\b(password|passwd|secret|api_?key|apikey|access_?token|private_?key)\s*[:=]\s*["'][^"']{4,200}["']"#,
    )
    .expect("RE_PASSWORD_ASSIGN: invalid regex")
});

// Test/mock/fake/dummy prefix exclusion — only at variable name position
static RE_TEST_PREFIX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(test_?|mock_?|fake_?|dummy_?|example_?|placeholder_?)\w*\s*=")
        .expect("RE_TEST_PREFIX: invalid regex")
});

struct SecretPattern {
    pattern: &'static Lazy<Regex>,
    apply_test_exclusion: bool,
    message: &'static str,
}

static SECRET_PATTERNS: [SecretPattern; 4] = [
    SecretPattern {
        pattern: &RE_KNOWN_PREFIX,
        apply_test_exclusion: false,
        message: "Hardcoded API token detected (matches known prefix pattern). Use environment variables or secret management.",
    },
    SecretPattern {
        pattern: &RE_BEARER_TOKEN,
        apply_test_exclusion: false,
        message: "Hardcoded Bearer/Basic token detected. Use environment variables or secret management.",
    },
    SecretPattern {
        pattern: &RE_PASSWORD_ASSIGN,
        apply_test_exclusion: true,
        message: "Hardcoded password/secret assignment detected. Use environment variables or secret management.",
    },
    SecretPattern {
        pattern: &RE_AWS_KEY,
        apply_test_exclusion: false,
        message: "Hardcoded AWS access key detected. Use environment variables or secret management.",
    },
];

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_ALL_FILES.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let mut violations = Vec::new();

            for (line_num, line) in non_comment_lines(content) {
                let is_test_line = RE_TEST_PREFIX.is_match(line);
                for sp in &SECRET_PATTERNS {
                    // SEC-006: Only apply test prefix exclusion to password assignments
                    if sp.apply_test_exclusion && is_test_line {
                        continue;
                    }
                    if sp.pattern.is_match(line) {
                        violations.push(Violation {
                            rule: super::rule_id::HARDCODED_SECRET.to_string(),
                            severity: Severity::Critical,
                            failure: sp.message.to_string(),
                            file: file_path.to_string(),
                            line: Some(line_num),
                        });
                        break; // One violation per line
                    }
                }
            }

            violations
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str, path: &str) -> Vec<Violation> {
        let r = rule();
        if !r.file_pattern.is_match(path) {
            return Vec::new();
        }
        r.check(content, path)
    }

    // T-006: const API_KEY = "sk-abc123..." → Critical
    #[test]
    fn detects_sk_prefix_api_key() {
        let v = check(r#"const API_KEY = "sk-abc123def456";"#, "/src/config.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
    }

    // T-007: "Authorization": "Bearer eyJhb..." → Critical
    #[test]
    fn detects_bearer_token() {
        let v = check(
            r#""Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature""#,
            "/src/api.ts",
        );
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
    }

    // T-008: const password = "s3cret" → Critical
    #[test]
    fn detects_password_assignment() {
        let v = check(r#"const password = "s3cret";"#, "/src/auth.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
    }

    // T-009: const AKIA_KEY = "AKIAIOSFODNN7EXAMPLE" → Critical
    #[test]
    fn detects_aws_key() {
        let v = check(r#"const AKIA_KEY = "AKIAIOSFODNN7EXAMPLE";"#, "/src/aws.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
    }

    // T-010: const ghp_token = "ghp_..." → Critical
    #[test]
    fn detects_github_token() {
        let v = check(
            r#"const ghp_token = "ghp_xxxxxxxxxxxxxxxxxxxx";"#,
            "/src/github.ts",
        );
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
    }

    // T-011: const test_token = "sk-abc" → 0 violations (test prefix)
    #[test]
    fn ignores_test_prefix() {
        assert!(check(r#"const test_token = "sk-abc";"#, "/src/test.ts").is_empty());
    }

    // T-012: const mock_password = "x" → 0 violations (mock prefix)
    #[test]
    fn ignores_mock_prefix() {
        assert!(check(r#"const mock_password = "x";"#, "/src/mock.ts").is_empty());
    }

    // T-013: // API_KEY = "sk-abc" (comment) → 0 violations
    #[test]
    fn ignores_comment() {
        assert!(check(r#"// const API_KEY = "sk-abc123";"#, "/src/config.ts").is_empty());
    }

    // T-014: const theme = "dark" → 0 violations (non-sensitive)
    #[test]
    fn ignores_non_sensitive() {
        assert!(check(r#"const theme = "dark";"#, "/src/config.ts").is_empty());
    }

    // SEC-006: test prefix should NOT suppress real secret values (sk-, AKIA)
    #[test]
    fn test_prefix_does_not_suppress_secret_value() {
        let v = check(
            r#"const test_key = "sk-REALSECRETKEY123";"#,
            "/src/config.ts",
        );
        assert_eq!(
            v.len(),
            1,
            "Real sk- secret should be detected even with test_ prefix"
        );
    }

    // SEC-006: test prefix should NOT suppress Bearer tokens
    #[test]
    fn test_prefix_does_not_suppress_bearer() {
        let v = check(
            r#"const test_auth = "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature""#,
            "/src/config.ts",
        );
        assert_eq!(
            v.len(),
            1,
            "Bearer token should be detected even with test_ prefix"
        );
    }

    // SEC-004: short password values (UI labels etc) should not trigger
    #[test]
    fn ignores_short_password_value() {
        // type: "password" has short value, shouldn't trigger
        assert!(check(r#"const config = { password: "***" };"#, "/src/config.ts").is_empty());
    }

    // SEC-004: real password with sufficient length should trigger
    #[test]
    fn detects_password_with_sufficient_length() {
        let v = check(r#"const password = "s3cret123";"#, "/src/auth.ts");
        assert_eq!(v.len(), 1);
    }

    // INT-009: Slack bot token (xoxb-) should be detected
    #[test]
    fn detects_slack_bot_token() {
        let v = check(r#"const token = "xoxb-abcdefghij1234";"#, "/src/slack.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
    }

    // INT-009: GitLab personal access token (glpat-) should be detected
    #[test]
    fn detects_gitlab_token() {
        let v = check(r#"const token = "glpat-abcdefghij1234";"#, "/src/gitlab.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Critical);
    }

    // INT-010: error messages differ between known prefix and bearer token matches
    #[test]
    fn error_messages_differ_per_pattern() {
        let v_prefix = check(r#"const key = "sk-abc123def456";"#, "/src/config.ts");
        let v_bearer = check(
            r#""Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature""#,
            "/src/api.ts",
        );
        assert_eq!(v_prefix.len(), 1);
        assert_eq!(v_bearer.len(), 1);
        assert_ne!(
            v_prefix[0].failure, v_bearer[0].failure,
            "Known prefix and bearer token should have different error messages"
        );
        assert!(
            v_prefix[0].failure.contains("known prefix pattern"),
            "Known prefix message should mention 'known prefix pattern'"
        );
        assert!(
            v_bearer[0].failure.contains("Bearer/Basic"),
            "Bearer message should mention 'Bearer/Basic'"
        );
    }

    // INT-015: test prefix with word boundary matches without declaration keywords
    #[test]
    fn test_prefix_matches_without_declaration_keyword() {
        // No "const/let/var" — just a direct assignment like in a config object
        assert!(check(r#"test_password = "s3cret123";"#, "/src/config.ts").is_empty());
    }
}
