use super::{non_comment_lines, Rule, Severity, Violation, RE_JS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

// location.href = <variable> or window.location = <variable>
// Excludes string literals and relative-path template literals
static RE_LOCATION_ASSIGN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(^|[^.\w])(window\.|document\.)?location(\.href)?\s*=\s*[a-zA-Z_$]"#)
        .expect("RE_LOCATION_ASSIGN: invalid regex")
});

// location.replace(<variable>) or location.assign(<variable>)
static RE_LOCATION_CALL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(^|[^.\w])(window\.|document\.)?location\.(assign|replace)\s*\(\s*[a-zA-Z_$]"#)
        .expect("RE_LOCATION_CALL: invalid regex")
});

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let mut violations = Vec::new();

            for (line_num, line) in non_comment_lines(content) {
                if RE_LOCATION_ASSIGN.is_match(line) || RE_LOCATION_CALL.is_match(line) {
                    violations.push(Violation {
                        rule: super::rule_id::OPEN_REDIRECT.to_string(),
                        severity: Severity::High,
                        failure:
                            "Validate URL before redirect. Use allowlist or ensure relative path."
                                .to_string(),
                        file: file_path.to_string(),
                        line: Some(line_num),
                    });
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

    // T-026: location.href = redirectUrl → 1 violation, High
    #[test]
    fn detects_location_href_variable() {
        let v = check("location.href = redirectUrl;", "/src/auth.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-027: location.replace(url) → 1 violation
    #[test]
    fn detects_location_replace() {
        let v = check("location.replace(url);", "/src/auth.ts");
        assert_eq!(v.len(), 1);
    }

    // T-028: window.location = target → 1 violation
    #[test]
    fn detects_window_location_assign() {
        let v = check("window.location = target;", "/src/auth.ts");
        assert_eq!(v.len(), 1);
    }

    // T-029: location.href = "/dashboard" → 0 violations (literal)
    #[test]
    fn allows_string_literal() {
        assert!(check(r#"location.href = "/dashboard";"#, "/src/auth.ts").is_empty());
    }

    // T-030: location.href = `/users/${id}` → 0 violations (relative path)
    #[test]
    fn allows_relative_template() {
        assert!(check("location.href = `/users/${id}`;", "/src/auth.ts").is_empty());
    }

    // T-031: // location.href = x (comment) → 0 violations
    #[test]
    fn ignores_comment() {
        assert!(check("// location.href = x;", "/src/auth.ts").is_empty());
    }

    // SEC-005: document.location = url
    #[test]
    fn detects_document_location() {
        assert_eq!(check("document.location = url;", "/src/auth.ts").len(), 1);
    }

    // SEC-005: document.location.href = url
    #[test]
    fn detects_document_location_href() {
        assert_eq!(
            check("document.location.href = url;", "/src/auth.ts").len(),
            1
        );
    }

    // TC-002: location.assign(url)
    #[test]
    fn detects_location_assign() {
        assert_eq!(check("location.assign(url);", "/src/auth.ts").len(), 1);
    }

    // INT-004: relocation.href should NOT be detected (false positive prevention)
    #[test]
    fn ignores_relocation_href() {
        assert!(check("relocation.href = url;", "/src/auth.ts").is_empty());
    }

    // INT-004: document.location = url should still be detected
    #[test]
    fn detects_document_location_assign_var() {
        assert_eq!(check("document.location = url;", "/src/auth.ts").len(), 1);
    }
}
